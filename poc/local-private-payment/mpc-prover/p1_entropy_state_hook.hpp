#pragma once

// Private, child-local entropy-ingress evidence for the corrupt-P1 state
// capsule. Raw entropy is retained only in the private state archive. This
// hook is evidence transport, not a recorder factory or public receipt.

#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace kpb::measurement::p1_state_capsule {
class P1CorruptStateRecorderAuthority;
class P1StateThreadEpochAuthority;
class P1EntropyStateAdapter;

// Complete before either private friendship grant. The live recorder and the
// adapter both friend this exact class, so a standalone include cannot forge a
// same-name recorder or bridge to construct the adapter.
class P1EntropyStateAdapterFactoryBridge final {
    P1EntropyStateAdapterFactoryBridge() = delete;
public:
    static std::unique_ptr<P1EntropyStateAdapter> take(
        P1CorruptStateRecorderAuthority&,
        const P1StateThreadEpochAuthority&);
};
}

namespace kpi::mpc::p1_private_state {

enum class EntropySource : std::uint8_t {
    MpSpdzPrngReseed = 1,
    SimplestOtRandomBytes = 2,
    CryptoToolsSystemSeed = 3,
};

inline constexpr std::string_view entropy_source_domain(EntropySource source) {
    switch (source) {
    case EntropySource::MpSpdzPrngReseed:
        return "MP-SPDZ/Tools/random.cpp:PRNG::ReSeed";
    case EntropySource::SimplestOtRandomBytes:
        return "MP-SPDZ/deps/SimplestOT_C/common/randombytes.c:"
               "simplestot_randombytes";
    case EntropySource::CryptoToolsSystemSeed:
        return "MP-SPDZ/deps/libOTe2/cryptoTools/cryptoTools/Common/"
               "Defines.cpp:osuCrypto::sysRandomSeed";
    }
    return {};
}

inline constexpr std::uint64_t entropy_source_width(EntropySource source) {
    switch (source) {
    case EntropySource::MpSpdzPrngReseed:
    case EntropySource::CryptoToolsSystemSeed:
        return 16;
    case EntropySource::SimplestOtRandomBytes:
        return 32;
    }
    return 0;
}

// Each wrapper call creates one source-owned entropy-result object. Epochs are
// assigned by the installed ingress recorder and never derived from pointers,
// pthread_t, addresses, paths, or caller digests.
struct EntropyIngressView final {
    EntropySource source{};
    // Return-site offset within the selected executable image. This is never
    // an absolute pointer. A future selected manifest must bind each allowed
    // RVA to its exact source/build identity before live completeness is true.
    std::uint64_t callsite_rva{};
    std::uint64_t object_epoch{};
    std::uint64_t thread_epoch{};
    std::uint64_t allocation_epoch{};
    std::uint64_t counter_before{};
    std::uint64_t counter_after{};
    std::span<const unsigned char> exact_entropy;
};

namespace entropy_detail {

inline void append_u64(
        std::vector<unsigned char>& output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        output.push_back(static_cast<unsigned char>(value >> shift));
}

inline void append_bytes(
        std::vector<unsigned char>& output,
        std::span<const unsigned char> value) {
    if (value.size() > std::numeric_limits<std::uint64_t>::max() ||
        output.size() > std::numeric_limits<std::size_t>::max() - 8 ||
        value.size() >
            std::numeric_limits<std::size_t>::max() - output.size() - 8)
        throw std::runtime_error("P1-entropy-state-size-overflow");
    append_u64(output, value.size());
    output.insert(output.end(), value.begin(), value.end());
}

} // namespace entropy_detail

// Canonical private payload. Integers are big-endian u64. The exact pinned
// source-site domain precedes the raw entropy, preventing family relabelling.
inline std::vector<unsigned char> encode_entropy_ingress(
        const EntropyIngressView& value) {
    const auto source = static_cast<std::uint64_t>(value.source);
    const auto domain = entropy_source_domain(value.source);
    const auto width = entropy_source_width(value.source);
    if (source == 0 || source > 3 || domain.empty() || width == 0 ||
        value.callsite_rva == 0 || value.object_epoch == 0 ||
        value.thread_epoch == 0 ||
        value.allocation_epoch == 0 ||
        value.counter_before == std::numeric_limits<std::uint64_t>::max() ||
        value.counter_after != value.counter_before + 1 ||
        value.exact_entropy.size() != width)
        throw std::runtime_error("invalid-P1-entropy-ingress-event");

    static constexpr std::string_view prefix =
        "KPI_P1_ENTROPY_INGRESS_STATE_V2\n";
    std::vector<unsigned char> output;
    // Seven scalar fields plus two length prefixes. Exact reservation avoids
    // leaving stale raw-entropy copies behind during vector reallocation.
    output.reserve(prefix.size() + 9 * 8 + domain.size() + width);
    output.insert(output.end(), prefix.begin(), prefix.end());
    for (const auto field : {
             source, value.callsite_rva, value.object_epoch,
             value.thread_epoch,
             value.allocation_epoch, value.counter_before,
             value.counter_after})
        entropy_detail::append_u64(output, field);
    entropy_detail::append_bytes(
        output, std::span(
            reinterpret_cast<const unsigned char*>(domain.data()),
            domain.size()));
    entropy_detail::append_bytes(output, value.exact_entropy);
    return output;
}

class EntropyStateHook {
    EntropyStateHook() = default;
    friend class ::kpb::measurement::p1_state_capsule::P1EntropyStateAdapter;
#ifdef KPI_P1_ENTROPY_STATE_HOOK_TEST_SETUP
protected:
    struct TestOnlyConstruction final {};
    explicit EntropyStateHook(TestOnlyConstruction) {}
#endif

public:
    EntropyStateHook(const EntropyStateHook&) = delete;
    EntropyStateHook& operator=(const EntropyStateHook&) = delete;
    virtual ~EntropyStateHook() = default;
    virtual bool record_entropy_ingress(
        const EntropyIngressView&) noexcept = 0;
    // Called exactly once after every selected source thread has joined and
    // the wrappers are uninstalled. False leaves all three families missing.
    virtual bool entropy_capture_terminal_noexcept() noexcept = 0;
    virtual void entropy_unavailable_noexcept(EntropySource) noexcept = 0;
};

struct EntropyStateHookSourceStatus final {
    bool canonical_raw_entropy_encoding{};
    bool source_site_domains_fixed{};
    bool selected_executable_callsite_rva_retained{};
    bool source_callsite_manifest_bound{};
    bool mp_spdz_reseed_wrapper{};
    bool simplest_ot_randombytes_wrapper{};
    bool crypto_tools_system_seed_wrapper{};
    bool capsule_family_adapter{};
    bool selected_role1_installation{};
    bool complete_corrupt_p1_view{};
    bool configured{};
};

inline constexpr EntropyStateHookSourceStatus kEntropyStateHookSourceStatus{
    .canonical_raw_entropy_encoding = true,
    .source_site_domains_fixed = true,
    .selected_executable_callsite_rva_retained = true,
    .source_callsite_manifest_bound = false,
    .mp_spdz_reseed_wrapper = true,
    .simplest_ot_randombytes_wrapper = true,
    .crypto_tools_system_seed_wrapper = true,
    .capsule_family_adapter = false,
    .selected_role1_installation = false,
    .complete_corrupt_p1_view = false,
    .configured = false,
};

} // namespace kpi::mpc::p1_private_state

namespace kpb::measurement::p1_state_capsule {

// Complete before any friendship grant. Only the live recorder will construct
// this adapter after the capsule implementation adds its shared-ledger seam.
class P1EntropyStateAdapter final
    : public kpi::mpc::p1_private_state::EntropyStateHook {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit P1EntropyStateAdapter(std::unique_ptr<Storage>);
    friend class P1EntropyStateAdapterFactoryBridge;

public:
    P1EntropyStateAdapter(const P1EntropyStateAdapter&) = delete;
    P1EntropyStateAdapter& operator=(const P1EntropyStateAdapter&) = delete;
    P1EntropyStateAdapter(P1EntropyStateAdapter&&) = delete;
    P1EntropyStateAdapter& operator=(P1EntropyStateAdapter&&) = delete;
    ~P1EntropyStateAdapter() override;
    bool record_entropy_ingress(
        const kpi::mpc::p1_private_state::EntropyIngressView&) noexcept
        override;
    bool entropy_capture_terminal_noexcept() noexcept override;
    void entropy_unavailable_noexcept(
        kpi::mpc::p1_private_state::EntropySource) noexcept override;
};

} // namespace kpb::measurement::p1_state_capsule
