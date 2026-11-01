#pragma once

// Private child-local recorder contract for the exact Beaver multiplication
// state used by the pinned BN254/MASCOT financial process.  This is an
// isolated source slice: it has no production adapter, no public receipt, and
// cannot authorize an observer result.

#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace kpi::mpc::p1_private_state {
class BeaverStateHook;
class BeaverSourceScope;
class BeaverStateHookAccess;
enum class BeaverAbortClass : std::uint8_t;
}

namespace kpb::measurement::p1_state_capsule {
class P1BeaverStateAdapter;

class P1BeaverStateAdapterFactoryBridge final {
    P1BeaverStateAdapterFactoryBridge() = delete;
    friend class P1BeaverStateAdapter;

    static std::unique_ptr<
        ::kpi::mpc::p1_private_state::BeaverSourceScope>
    install_source_scope(
        ::kpi::mpc::p1_private_state::BeaverStateHook&,
        std::uint64_t persistent_child_epoch,
        std::uint64_t root_thread_epoch, std::uint64_t local_role,
        std::uint64_t player_count);
    static bool round_begin(
        ::kpi::mpc::p1_private_state::BeaverSourceScope&,
        std::uint64_t round) noexcept;
    static bool batch_begin(
        ::kpi::mpc::p1_private_state::BeaverSourceScope&,
        std::uint64_t scalar_capture_site,
        std::uint64_t expected_multiplications) noexcept;
    static bool round_end(
        ::kpi::mpc::p1_private_state::BeaverSourceScope&,
        std::uint64_t round) noexcept;
    static bool abort(
        ::kpi::mpc::p1_private_state::BeaverSourceScope&,
        ::kpi::mpc::p1_private_state::BeaverAbortClass) noexcept;
    static bool finish(
        std::unique_ptr<
            ::kpi::mpc::p1_private_state::BeaverSourceScope>&&) noexcept;

#ifdef KPI_P1_BEAVER_STATE_HOOK_TEST_SETUP
public:
    static std::unique_ptr<
        ::kpi::mpc::p1_private_state::BeaverSourceScope>
    test_only_install_source_scope(
        ::kpi::mpc::p1_private_state::BeaverStateHook&,
        std::uint64_t persistent_child_epoch,
        std::uint64_t root_thread_epoch, std::uint64_t local_role,
        std::uint64_t player_count);
    static bool test_only_round_begin(
        ::kpi::mpc::p1_private_state::BeaverSourceScope&,
        std::uint64_t round) noexcept;
    static bool test_only_batch_begin(
        ::kpi::mpc::p1_private_state::BeaverSourceScope&,
        std::uint64_t scalar_capture_site,
        std::uint64_t expected_multiplications) noexcept;
    static bool test_only_round_end(
        ::kpi::mpc::p1_private_state::BeaverSourceScope&,
        std::uint64_t round) noexcept;
    static bool test_only_abort(
        ::kpi::mpc::p1_private_state::BeaverSourceScope&,
        ::kpi::mpc::p1_private_state::BeaverAbortClass) noexcept;
    static bool test_only_finish(
        std::unique_ptr<
            ::kpi::mpc::p1_private_state::BeaverSourceScope>&&) noexcept;
#endif
};
}

namespace kpi::mpc::p1_private_state {

inline constexpr std::string_view BEAVER_STATE_DOMAIN =
    "KPI_P1_BEAVER_STATE_V1\n";
inline constexpr std::string_view BEAVER_SELECTED_COMMIT =
    "113c4e47dd94bca9ecab029d2f0abe649bea5c52";
inline constexpr std::string_view BEAVER_SELECTED_TYPE =
    "MP-SPDZ::Beaver<Share<gfp_<0,4>>>/MASCOT/BN254";
inline constexpr std::string_view BEAVER_SOURCE_CLOSURE_MANIFEST =
    "KPI_P1_BEAVER_SOURCE_MANIFEST_V2\n"
    "commit=113c4e47dd94bca9ecab029d2f0abe649bea5c52\n"
    "Protocols/Beaver.h=3b78442bda051b4d9280913a2636a867a64f1c4d198d426c2547bb98dbcb58e7\n"
    "Protocols/Beaver.hpp=b33e2952d239f46aa6791f5716c393b149304f2c2632e6a8205df29fab8bf4fb\n"
    "Protocols/MascotPrep.h=579541d2ec20cdfdf44cd75e0098eb4635c8c61bf4439d20494d6e395f800d8e\n"
    "Protocols/MascotPrep.hpp=5b33a46627bca22393f85153d8b8dc42c9c0e3568b3c51049125a5445f309946\n"
    "Protocols/ReplicatedPrep.h=5dc4ea560a401c6b2290aa33e439344e802e68950f086587293302df58b2c7f8\n"
    "Protocols/ReplicatedPrep.hpp=8e65e6ae1dcb281a22e3de47c6bf5dfe5dfdec9451f6a29b821a87ae800e7841\n"
    "Processor/Data_Files.h=3b3390da880fa893b8f47b56abd754f49095ddfd6e1e70ef4ef913593fe68820\n"
    "Protocols/ProtocolSet.h=d867438ad43b190fd4f4bab0163654d6c85303bb04bf265df926e2d530569398\n"
    "Protocols/Share.h=e657f7d39b6d9bf8f5b4e07123157c0d34b02619f162104801da00b9ea136520\n"
    "Protocols/SemiShare.h=8aff83bff276d31820a7320c63afb3db8a0ac48a4fffec8abd85659ecb3cede7\n"
    "Protocols/SPDZ.h=962a7fd6418e5673bb5d21e6e21abe10e54709ab1843dd482511e70726289d3c\n"
    "Protocols/Hemi.h=54b2606605e329b9580fd93dd2461bc3069999e51f5f2ec9a377266c641c6cb5\n"
    "Protocols/Replicated.h=0c44a58a15f0ba7ee7e77daabea4f3674460e3919f4cbcd6257fcbe8ef001294\n"
    "Protocols/Replicated.hpp=cecd7a6abf1f22d064ccb2901ba1b8ff64ab275f9666da417615c79358901953\n"
    "Math/gfp.h=3b9af0a4a83abeda72d8e48a5c90f88b2497368d964b829d50f6ef8e0092e912\n"
    "Tools/octetStream.h=6baba448a8e7ebfdf640d2ceffd77ba1b772ef833cef1d482207fc0d55835397\n"
    "Tools/PointerVector.h=93e771981a8a116033e26dd0e0891264e09bb9ef093a2e930280b555eec2b10f\n"
    "local/auth_field.cpp=023c254f47c0b6c76cec3aba1b4313582cadd2f2931bfd26d49d7052d722047a\n"
    "local/auth_field.hpp=83971859243b60d074974214c8050195199b2cfa888e01774b39a6a7511ef198\n"
    "local/p1_scalar_capture_manifest.hpp=1fa2e6c168804187b98d35a7d91bd3231fa506f6f23dc9a210ae9fe6c60dc7e8\n"
    "overlay/mp-spdz-p1-beaver-state-v1.patch=11b646cb05257d3a70ed32df19a67579a39efdaf5c1b5ca49b1b3694512cc1ef\n"
    "post/Protocols/Beaver.hpp=05fa49b197da6dc91a15178708c9c0b4b04d6117be6c47bd27f7c515a4b355dc\n"
    "post/Protocols/MascotPrep.hpp=f81df667d0cf357f526bf13b58da873a0578fdabae30019324825e7308cf1b9d\n"
    "post/Protocols/ReplicatedPrep.hpp=5069278c110e652cbd49c51711edfa2b29284bf91bda5871785ef3dcf7eb874a\n";

enum class BeaverEventKind : std::uint8_t {
    Construct = 1,
    RoundBegin = 2,
    CacheBatchGenerated = 3,
    CacheTriplePop = 4,
    BatchBegin = 5,
    Init = 6,
    Prepare = 7,
    TripleMask = 8,
    OpenedResult = 9,
    FinalizeReturn = 10,
    BatchTerminal = 11,
    RoundEnd = 12,
    Abort = 13,
};

enum class BeaverAbortClass : std::uint8_t {
    None = 0,
    SourceRejected = 1,
    UpstreamException = 2,
    PartialBatch = 3,
    ScopeUnlinked = 4,
    TerminalIncomplete = 5,
};

enum class BeaverPhase : std::uint8_t {
    Constructed = 1,
    BetweenRounds = 2,
    Round = 3,
    BatchDeclared = 4,
    Initialized = 5,
    Prepared = 6,
    Exchanged = 7,
    Finalizing = 8,
    BatchComplete = 9,
    Terminal = 10,
    Unavailable = 11,
};

// `source_state` is an event-specific, source-owned canonical encoding.  It
// contains no object address, allocator padding, pthread identity, file path,
// or caller-supplied digest.  The private adapter must consume it
// synchronously and preserve the exact bytes.
struct BeaverEventView final {
    BeaverEventKind kind{};
    BeaverAbortClass abort_class{BeaverAbortClass::None};
    BeaverPhase phase{BeaverPhase::Constructed};
    std::uint64_t sequence{};
    std::uint64_t persistent_child_epoch{};
    std::uint64_t root_thread_epoch{};
    std::uint64_t round{};
    std::uint64_t round_event_index{};
    std::uint64_t batch_epoch{};
    std::uint64_t scalar_capture_site{};
    std::uint64_t expected_multiplications{};
    std::uint64_t item_index{};
    std::uint64_t cache_epoch{};
    std::uint64_t cache_size_before{};
    std::uint64_t cache_size_after{};
    std::uint64_t local_role{};
    std::uint64_t player_count{};
    bool source_succeeded{};
    std::string_view source_site;
    std::string_view source_identity_sha256;
    std::span<const unsigned char> source_state;
};

std::vector<unsigned char> encode_beaver_event(const BeaverEventView&);

class BeaverStateHook {
    BeaverStateHook() = default;
    friend class ::kpb::measurement::p1_state_capsule::
        P1BeaverStateAdapter;
    friend class BeaverSourceScope;
    friend class BeaverStateHookAccess;

    virtual bool record_beaver_event(const BeaverEventView&) noexcept = 0;
    virtual bool beaver_terminal_noexcept() noexcept = 0;
    virtual void beaver_unavailable_noexcept() noexcept = 0;

#ifdef KPI_P1_BEAVER_STATE_HOOK_TEST_SETUP
protected:
    struct TestOnlyConstruction final {};
    explicit BeaverStateHook(TestOnlyConstruction) {}
#endif

public:
    BeaverStateHook(const BeaverStateHook&) = delete;
    BeaverStateHook& operator=(const BeaverStateHook&) = delete;
    virtual ~BeaverStateHook() = default;
};

class BeaverSourceScope final {
public:
    struct Storage;

private:
    std::unique_ptr<Storage> storage_;
    BeaverSourceScope(
        BeaverStateHook&, std::uint64_t persistent_child_epoch,
        std::uint64_t root_thread_epoch, std::uint64_t local_role,
        std::uint64_t player_count);
    friend class ::kpb::measurement::p1_state_capsule::
        P1BeaverStateAdapterFactoryBridge;

#ifdef KPI_P1_BEAVER_STATE_HOOK_TEST_SETUP
    friend class BeaverStateTestBridge;
#endif

public:
    BeaverSourceScope(const BeaverSourceScope&) = delete;
    BeaverSourceScope& operator=(const BeaverSourceScope&) = delete;
    BeaverSourceScope(BeaverSourceScope&&) = delete;
    BeaverSourceScope& operator=(BeaverSourceScope&&) = delete;
    ~BeaverSourceScope();
};

#ifdef KPI_P1_BEAVER_STATE_HOOK_TEST_SETUP
class BeaverStateTestBridge final {
public:
    static std::unique_ptr<BeaverSourceScope> install(
        BeaverStateHook&, std::uint64_t persistent_child_epoch,
        std::uint64_t root_thread_epoch, std::uint64_t local_role,
        std::uint64_t player_count);
    static bool round_begin(BeaverSourceScope&, std::uint64_t) noexcept;
    static bool batch_begin(
        BeaverSourceScope&, std::uint64_t scalar_capture_site,
        std::uint64_t expected_multiplications) noexcept;
    static bool round_end(BeaverSourceScope&, std::uint64_t) noexcept;
    static bool abort(BeaverSourceScope&, BeaverAbortClass) noexcept;
    static bool finish(std::unique_ptr<BeaverSourceScope>&&) noexcept;
};
#endif

} // namespace kpi::mpc::p1_private_state
