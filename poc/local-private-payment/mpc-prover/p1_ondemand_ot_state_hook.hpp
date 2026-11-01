#pragma once

// Private, child-local evidence transport for the pinned MP-SPDZ
// OnDemandOTTripleSetup map. Player and pthread identities are used only for
// in-process correspondence. They are never serialized or accepted as
// evidence identities.

#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace kpi::mpc::p1_private_state {
class OnDemandOtStateHook;
class OnDemandOtStateScope;
}

namespace kpb::measurement::p1_state_capsule {
class P1OnDemandOtMapStateAdapter;

// This complete bridge precedes every friendship grant below. Only the
// concrete capsule adapter can call it; there is no public adapter take(), raw
// recorder, event sink, file descriptor, or digest surface.
class P1OnDemandOtMapStateAdapterFactoryBridge final {
    P1OnDemandOtMapStateAdapterFactoryBridge() = delete;
    friend class P1OnDemandOtMapStateAdapter;

    static std::unique_ptr<
        ::kpi::mpc::p1_private_state::OnDemandOtStateScope>
    install_source_scope(
        ::kpi::mpc::p1_private_state::OnDemandOtStateHook&,
        const void* source_player, std::uint64_t persistent_child_epoch,
        std::uint64_t player_epoch, std::uint64_t root_thread_epoch,
        std::uint64_t local_role, std::uint64_t player_count);
    static bool round_begin(
        ::kpi::mpc::p1_private_state::OnDemandOtStateScope&,
        std::uint64_t round) noexcept;
    static bool round_end(
        ::kpi::mpc::p1_private_state::OnDemandOtStateScope&,
        std::uint64_t round) noexcept;
};
}

namespace kpi::mpc::p1_private_state {

inline constexpr std::string_view ONDEMAND_OT_STATE_DOMAIN =
    "KPI_P1_ONDEMAND_OT_MAP_STATE_V2\n";
inline constexpr std::string_view ONDEMAND_OT_SELECTED_COMMIT =
    "113c4e47dd94bca9ecab029d2f0abe649bea5c52";
inline constexpr std::string_view ONDEMAND_OT_SELECTED_TYPE =
    "MP-SPDZ::OnDemandOTTripleSetup/MASCOT/BN254/Share<Fr>";
inline constexpr std::string_view ONDEMAND_OT_MAP_TYPE =
    "std::map<Player*,OTTripleSetup*,std::less<Player*>>";

// The digest is SHA-256 over this exact ASCII manifest. It binds the
// transitive source closure needed to interpret map lifetime, BaseOT PRNG
// evolution, PRNG timers/cursors, and the thread_local destructor.
inline constexpr std::string_view ONDEMAND_OT_SOURCE_CLOSURE_MANIFEST =
    "KPI_P1_ONDEMAND_OT_MAP_SOURCE_MANIFEST_V3\n"
    "commit=113c4e47dd94bca9ecab029d2f0abe649bea5c52\n"
    "OT/OTTripleSetup.h=93e71b45a31f1f5f17abde80d069ea559789bbf7d28555a2f4a44252c25f7c1b\n"
    "OT/OTTripleSetup.cpp=05d1988b32947701965a4e6fa891c285637c40678d2267828f7bf0ca355a61aa\n"
    "OT/BaseOT.h=7927264ca7a5c9dfb9e01524384ad4646a8fd61ab69161d3ab1e03c891e7db4c\n"
    "OT/BaseOT.cpp=a5c8dde6a916ba26a65057fd965cebcddac568e18b48351cea257de0f8604f14\n"
    "Tools/random.h=6c49878e56256484f543166bb88419119688140188f1a08467329e6321d16989\n"
    "Tools/random.cpp=2ae51e81e57dc4f1a005d597485b9fbc8e93fa8fa799615d555402cfe5a5ced9\n"
    "Tools/BitVector.h=41c00045fd9566fe9940b7e49e55d5ba6cd9fb8dfd04cbbb001da4b68ff3eb30\n"
    "Tools/BitVector.cpp=29a1e752f9b5591a2d329600969a943ceebe28baa49de7fb66b7b93f79ac6395\n"
    "Tools/time-func.h=ee3a79dd33147c1a911e406cb23670339579ddb7993b498a6c0656a77fa633bb\n"
    "Tools/time-func.cpp=1b33d15d7808454f85832520250cee0b33e5b7f368c1769403994a888bb5e367\n"
    "Processor/BaseMachine.h=05dfe4f0c2f7c9b91390f385281874ff1df757367322cbbdc7e107faa17e09e5\n"
    "Processor/BaseMachine.cpp=b32593e6233d64a44545393ea019b01f49a7f7bdf028e9880231f6f0f9c9ea3c\n"
    "overlay/p1_ondemand_ot_state_hook.cpp=001e5f101e0734d23d319a3844af359179540f0122d0859f6fbd21fef84b0189\n"
    "overlay/p1_ondemand_ot_source_capture.hpp=e21db07dc768ea4120a56cfa122af0df0b0143c8be047f8e90ddf795bf2b0e20\n"
    "overlay/mp-spdz-p1-ondemand-ot-state-v1.patch=62d21405210da6f16ad16407137e061b4ec9cd9818067a4c743e0da0b16aa2bd\n"
    "post/OT/BaseOT.h=680451fbe66ade706176ecb985c63d4894df3f92de5b2d5b48388c05b275e300\n"
    "post/OT/OTTripleSetup.cpp=a67a1dc732cfc08ec3d33ce44f74b8de2029f58267621d05eb7e7c59c9601f57\n"
    "post/OT/OTTripleSetup.h=7c327d038eecd1cf6e39d6caa24675a933dc419ef26c02a82099e4eb6aebcb36\n"
    "post/Tools/random.h=c589e08172acb762c7d32fb245b5aad0b9f9926cc0b4ee1df2ce8d855d2cdbea\n"
    "post/Tools/time-func.h=d948b6d8aa6bc6766be32f5246cd70a727c34fce775b3aa297509568ff75463a\n";
inline constexpr std::string_view ONDEMAND_OT_SOURCE_CLOSURE_SHA256 =
    "ffc655846a92274beb88fea846ecdbf499a051e5e801b6dbd9866d29d2bfd5ab";

enum class OnDemandOtEventKind : std::uint8_t {
    Construct = 1,
    RoundBegin = 2,
    MapLookup = 3,
    MapEntryCreateBegin = 4,
    PrngBeforeChoiceConsume = 5,
    PrngAfterChoiceConsume = 6,
    OtSetupWorkerBegin = 7,
    OtSetupWorkerEnd = 8,
    MapEntryCreated = 9,
    GetFreshBegin = 10,
    OtExtendBefore = 11,
    OtSeededInitialAdvance = 12,
    OtExtendStoredAdvance = 13,
    OtExtendReturnedAdvance = 14,
    GetFreshEnd = 15,
    RoundEnd = 16,
    MapDestructorBegin = 17,
    MapDestructorTerminal = 18,
    Abort = 19,
};

enum class OnDemandOtTransitionClass : std::uint8_t {
    Construct = 1,
    Round = 2,
    MapTopology = 3,
    PrngConsume = 4,
    OtSetup = 5,
    OtExtend = 6,
    Terminal = 7,
    Abort = 8,
};

enum class OnDemandOtMapBranch : std::uint8_t {
    None = 0,
    MissingCreate = 1,
    ExistingReuse = 2,
};

enum class OnDemandOtAbortClass : std::uint8_t {
    None = 0,
    SetupWorkerException = 1,
    SetupRootException = 2,
    GetFreshException = 3,
    SourceSerialization = 4,
    ScopeUnlinked = 5,
    TerminalPrefixIncomplete = 6,
};

enum class OnDemandOtPhase : std::uint8_t {
    None = 0,
    Constructed = 1,
    BetweenRounds = 2,
    Round = 3,
    LookupMissing = 4,
    Creating = 5,
    LookupReady = 6,
    Fresh = 7,
    ExtendBefore = 8,
    SeededInitial = 9,
    StoredAdvanced = 10,
    Destructor = 11,
    Terminal = 12,
    Poisoned = 13,
};

enum class OnDemandOtSnapshotMask : std::uint8_t {
    None = 0,
    StateBefore = 1,
    StoredAfter = 2,
    ReturnedAfter = 4,
    Prng = 8,
};

constexpr OnDemandOtSnapshotMask operator|(
        OnDemandOtSnapshotMask left, OnDemandOtSnapshotMask right) noexcept {
    return static_cast<OnDemandOtSnapshotMask>(
        static_cast<unsigned>(left) | static_cast<unsigned>(right));
}

struct OnDemandOtEventDescriptor final {
    OnDemandOtEventKind kind{};
    OnDemandOtTransitionClass transition{};
    OnDemandOtSnapshotMask snapshots{};
    std::string_view source_site;
    // Exact upstream file SHA-256 for upstream callsites, or the exact local
    // source-manifest SHA-256 for adapter-owned lifecycle/abort callsites.
    std::string_view source_identity_sha256;
};

struct OnDemandOtManifestStep final {
    OnDemandOtEventKind kind{};
    OnDemandOtMapBranch branch{OnDemandOtMapBranch::None};
    std::uint64_t peer_index{};
    std::uint64_t peer_role{};

    friend bool operator==(
        const OnDemandOtManifestStep&, const OnDemandOtManifestStep&) =
        default;
};

std::span<const OnDemandOtEventDescriptor> ondemand_ot_event_descriptors();
const OnDemandOtEventDescriptor& ondemand_ot_event_descriptor(
    OnDemandOtEventKind);

// Returns the canonical peer-normalized grammar. Real worker event sequence
// remains captured exactly and may interleave; an adapter normalizes only the
// worker subgraph by peer before comparing with this manifest.
std::vector<OnDemandOtManifestStep> recompute_ondemand_ot_branch_manifest(
    std::uint64_t round, std::span<const OnDemandOtMapBranch> calls,
    std::uint64_t local_role, std::uint64_t player_count,
    bool include_construct, bool include_map_destructor_terminal);

// Every span is a source-owned field-wise canonical encoding. It must never
// contain object padding, a Player pointer, pthread_t, an allocator address,
// or a filesystem path. The private adapter consumes each span synchronously.
struct OnDemandOtEventView final {
    OnDemandOtEventKind kind{};
    OnDemandOtTransitionClass transition{};
    OnDemandOtMapBranch branch{OnDemandOtMapBranch::None};
    OnDemandOtAbortClass abort_class{OnDemandOtAbortClass::None};
    OnDemandOtPhase phase{OnDemandOtPhase::None};
    std::uint64_t sequence{};
    std::uint64_t persistent_child_epoch{};
    std::uint64_t player_epoch{};
    std::uint64_t root_thread_epoch{};
    std::uint64_t worker_thread_epoch{};
    std::uint64_t round{};
    std::uint64_t call_in_round{};
    std::uint64_t map_entry_epoch{};
    std::uint64_t local_role{};
    std::uint64_t player_count{};
    std::uint64_t peer_role{};
    std::uint64_t peer_index{};
    std::uint64_t map_size_before{};
    std::uint64_t map_size_after{};
    bool map_entry_found{};
    bool source_succeeded{};
    std::string_view source_site;
    std::string_view source_identity_sha256;
    std::span<const unsigned char> state_before;
    std::span<const unsigned char> stored_after;
    std::span<const unsigned char> returned_after;
    std::span<const unsigned char> prng_state;
};

class OnDemandOtCanonicalBytes final {
    std::vector<unsigned char> value_;
    explicit OnDemandOtCanonicalBytes(std::vector<unsigned char>);
    friend OnDemandOtCanonicalBytes encode_ondemand_ot_event(
        const OnDemandOtEventView&);

public:
    OnDemandOtCanonicalBytes(const OnDemandOtCanonicalBytes&) = delete;
    OnDemandOtCanonicalBytes& operator=(const OnDemandOtCanonicalBytes&) =
        delete;
    OnDemandOtCanonicalBytes(OnDemandOtCanonicalBytes&&) noexcept;
    OnDemandOtCanonicalBytes& operator=(OnDemandOtCanonicalBytes&&) noexcept;
    ~OnDemandOtCanonicalBytes();
    std::span<const unsigned char> view() const noexcept { return value_; }
};

OnDemandOtCanonicalBytes encode_ondemand_ot_event(
    const OnDemandOtEventView&);

class OnDemandOtStateHook {
    OnDemandOtStateHook() = default;
    friend class ::kpb::measurement::p1_state_capsule::
        P1OnDemandOtMapStateAdapter;
    friend class OnDemandOtStateScope;

    virtual bool record_ondemand_ot_event(
        const OnDemandOtEventView&) noexcept = 0;
    virtual bool bind_ondemand_ot_worker_epoch(
        std::uint64_t peer_index, std::uint64_t peer_role,
        std::uint64_t& logical_worker_epoch) noexcept = 0;
    virtual bool ondemand_ot_terminal_noexcept() noexcept = 0;
    virtual void ondemand_ot_unavailable_noexcept() noexcept = 0;

#ifdef KPI_P1_ONDEMAND_OT_STATE_HOOK_TEST_SETUP
protected:
    struct TestOnlyConstruction final {};
    explicit OnDemandOtStateHook(TestOnlyConstruction) {}
#endif

public:
    OnDemandOtStateHook(const OnDemandOtStateHook&) = delete;
    OnDemandOtStateHook& operator=(const OnDemandOtStateHook&) = delete;
    virtual ~OnDemandOtStateHook() = default;
};

class OnDemandOtStateScope final {
public:
    // Opaque implementation name only; no storage or constructor is exposed.
    struct Storage;

private:
    std::unique_ptr<Storage> storage_;
    OnDemandOtStateScope(
        OnDemandOtStateHook&, const void* source_player,
        std::uint64_t persistent_child_epoch, std::uint64_t player_epoch,
        std::uint64_t root_thread_epoch, std::uint64_t local_role,
        std::uint64_t player_count);
    friend class ::kpb::measurement::p1_state_capsule::
        P1OnDemandOtMapStateAdapterFactoryBridge;
#ifdef KPI_P1_ONDEMAND_OT_STATE_HOOK_TEST_SETUP
    friend class OnDemandOtStateTestBridge;
#endif

public:
    OnDemandOtStateScope(const OnDemandOtStateScope&) = delete;
    OnDemandOtStateScope& operator=(const OnDemandOtStateScope&) = delete;
    OnDemandOtStateScope(OnDemandOtStateScope&&) = delete;
    OnDemandOtStateScope& operator=(OnDemandOtStateScope&&) = delete;
    ~OnDemandOtStateScope();
};

// Exact pinned source methods. False means no selected private scope exists.
// A malformed event poisons an installed scope and returns true so the
// upstream call cannot mistake failed capture for an unselected execution.
class OnDemandOtStateSourceBridge final {
    OnDemandOtStateSourceBridge() = delete;
public:
    static bool capture_required_noexcept(
        const void* source_player, std::uint64_t local_role,
        std::uint64_t player_count) noexcept;
    static bool capture_required_pointer_noexcept(
        const void* source_player) noexcept;
    static bool map_lookup(
        const void* source_player, std::uint64_t map_size_before,
        bool found, std::span<const unsigned char> entry_before) noexcept;
    static bool map_entry_create_begin(const void* source_player) noexcept;
    static bool prng_before_choice_consume(
        const void* source_player,
        std::span<const unsigned char> exact_prng_state) noexcept;
    static bool prng_after_choice_consume(
        const void* source_player,
        std::span<const unsigned char> exact_prng_state) noexcept;
    static bool ot_setup_worker_begin(
        const void* source_player, std::uint64_t peer_index,
        std::uint64_t peer_role) noexcept;
    static bool ot_setup_worker_end(
        const void* source_player, std::uint64_t peer_index,
        std::uint64_t peer_role, bool succeeded) noexcept;
    static bool map_entry_created(
        const void* source_player, std::uint64_t map_size_after,
        std::span<const unsigned char> entry_after) noexcept;
    static bool get_fresh_begin(
        const void* source_player,
        std::span<const unsigned char> entry_before) noexcept;
    static bool ot_extend_before(
        const void* source_player, std::uint64_t peer_index,
        std::uint64_t peer_role,
        std::span<const unsigned char> setup_before) noexcept;
    static bool ot_seeded_initial_advance(
        const void* source_player, std::uint64_t peer_index,
        std::uint64_t peer_role,
        std::span<const unsigned char> seeded_base) noexcept;
    static bool ot_extend_stored_advance(
        const void* source_player, std::uint64_t peer_index,
        std::uint64_t peer_role,
        std::span<const unsigned char> stored_setup,
        std::span<const unsigned char> first_advanced_base) noexcept;
    static bool ot_extend_returned_advance(
        const void* source_player, std::uint64_t peer_index,
        std::uint64_t peer_role,
        std::span<const unsigned char> returned_base) noexcept;
    static bool get_fresh_end(
        const void* source_player, std::uint64_t map_size_after,
        std::span<const unsigned char> stored_entry_after,
        std::span<const unsigned char> returned_setup) noexcept;
    static bool map_destructor_begin(
        const void* source_player, std::uint64_t map_size_before,
        std::span<const unsigned char> exact_map_state,
        std::span<const unsigned char> exact_entry_state) noexcept;
    static bool map_destructor_terminal(
        const void* source_player, std::uint64_t map_size_after) noexcept;
    static void empty_map_destructor_noexcept() noexcept;
    static void setup_root_abort_noexcept(const void* source_player) noexcept;
    static void get_fresh_abort_noexcept(const void* source_player) noexcept;
    static void source_serialization_abort_noexcept(
        const void* source_player) noexcept;
    static void unavailable_noexcept() noexcept;
};

#ifdef KPI_P1_ONDEMAND_OT_STATE_HOOK_TEST_SETUP
class OnDemandOtStateTestBridge final {
    OnDemandOtStateTestBridge() = delete;
public:
    static std::unique_ptr<OnDemandOtStateScope> install(
        OnDemandOtStateHook&, const void* source_player,
        std::uint64_t persistent_child_epoch, std::uint64_t player_epoch,
        std::uint64_t root_thread_epoch, std::uint64_t local_role,
        std::uint64_t player_count);
    static bool round_begin(
        OnDemandOtStateScope&, std::uint64_t round) noexcept;
    static bool round_end(
        OnDemandOtStateScope&, std::uint64_t round) noexcept;
};
#endif

} // namespace kpi::mpc::p1_private_state
