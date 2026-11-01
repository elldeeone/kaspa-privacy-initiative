#pragma once

// Feasibility-aware Observer v4 output grammar.  The fixed bytes describe the
// required family graph but are never authority; the native acceptance bridge
// must separately consume every live opaque capability.

#include "privacy_measurement_output_abi.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace kpb::measurement::runtime_bridge {

inline constexpr std::uint64_t OBSERVER_V4_PREFIX_BYTES =
    OBSERVER_OUTPUT_ABI.exact_bytes;
inline constexpr std::uint64_t OBSERVER_V4_SECTION_OFFSET =
    OBSERVER_V4_PREFIX_BYTES;
inline constexpr std::uint64_t OBSERVER_V4_SECTION_BYTES = 640;
inline constexpr std::uint64_t OBSERVER_V4_USED_BYTES = 152192;
inline constexpr std::uint64_t OBSERVER_V4_EXACT_BYTES = 155648;
inline constexpr std::array<unsigned char, 8> OBSERVER_V4_SECTION_MAGIC{
    'K', 'P', 'B', 'O', 'A', 'V', '4', '1'};
inline constexpr std::uint32_t OBSERVER_V4_VERSION = 4;
inline constexpr std::uint16_t OBSERVER_V4_FLAGS = 3;

enum class ObserverV4Family : std::uint8_t {
    S4OutputGroth16 = 1,
    S12AggregateGroth16 = 2,
    S5CryptoboxConfidentiality = 3,
    S6aHiddenDeliveryPrf = 4,
    S7NullifierHmacPrf = 5,
    S5AndS6aConjunction = 6,
    JointS6aS7Hmac = 7,
    NarrowS14MpcRealization = 8,
    NarrowS14AndS12Conjunction = 9,
    CounterfactualFullW1Close = 10,
    AllFreshTrialHistoryDirectEmpirical = 11,
    SourceRuntimeFreshness = 12,
};

enum class ObserverV4RequirementMode : std::uint8_t {
    Independent = 1,
    StrictConjunction = 2,
    JointSameSourceGame = 3,
    AtomicSameInstance = 4,
    ExhaustiveFreshTrialHistory = 5,
    SourceRuntimeFreshness = 6,
};

enum class ObserverV4Applicability : std::uint8_t {
    // A pinned historical file or dependency checksum is not a live
    // applicability capability.  Every v4 family stays explicitly missing
    // until an opaque authority is consumed by the future acceptance bridge.
    MissingLiveAuthority = 0,
};

struct ObserverV4FamilyRow {
    ObserverV4Family family{};
    ObserverV4RequirementMode mode{};
    ObserverV4Applicability applicability{};
    std::uint8_t pinned_provenance_count{};
    std::uint16_t prerequisite_mask{};
    bool operator==(const ObserverV4FamilyRow&) const = default;
};

consteval std::uint16_t observer_v4_family_bit(ObserverV4Family family) {
    return static_cast<std::uint16_t>(
        1U << (static_cast<unsigned>(family) - 1U));
}

inline constexpr std::array<ObserverV4FamilyRow, 12>
    OBSERVER_V4_FAMILY_ROWS{{
        {ObserverV4Family::S4OutputGroth16,
         ObserverV4RequirementMode::Independent,
         ObserverV4Applicability::MissingLiveAuthority, 4, 0},
        {ObserverV4Family::S12AggregateGroth16,
         ObserverV4RequirementMode::Independent,
         ObserverV4Applicability::MissingLiveAuthority, 8, 0},
        {ObserverV4Family::S5CryptoboxConfidentiality,
         ObserverV4RequirementMode::Independent,
         ObserverV4Applicability::MissingLiveAuthority, 1, 0},
        {ObserverV4Family::S6aHiddenDeliveryPrf,
         ObserverV4RequirementMode::Independent,
         ObserverV4Applicability::MissingLiveAuthority, 0, 0},
        {ObserverV4Family::S7NullifierHmacPrf,
         ObserverV4RequirementMode::Independent,
         ObserverV4Applicability::MissingLiveAuthority, 0, 0},
        {ObserverV4Family::S5AndS6aConjunction,
         ObserverV4RequirementMode::StrictConjunction,
         ObserverV4Applicability::MissingLiveAuthority, 0,
         static_cast<std::uint16_t>(
             observer_v4_family_bit(
                 ObserverV4Family::S5CryptoboxConfidentiality) |
             observer_v4_family_bit(
                 ObserverV4Family::S6aHiddenDeliveryPrf))},
        {ObserverV4Family::JointS6aS7Hmac,
         ObserverV4RequirementMode::JointSameSourceGame,
         ObserverV4Applicability::MissingLiveAuthority, 0,
         static_cast<std::uint16_t>(
             observer_v4_family_bit(
                 ObserverV4Family::S6aHiddenDeliveryPrf) |
             observer_v4_family_bit(
                 ObserverV4Family::S7NullifierHmacPrf))},
        {ObserverV4Family::NarrowS14MpcRealization,
         ObserverV4RequirementMode::Independent,
         ObserverV4Applicability::MissingLiveAuthority, 0, 0},
        {ObserverV4Family::NarrowS14AndS12Conjunction,
         ObserverV4RequirementMode::StrictConjunction,
         ObserverV4Applicability::MissingLiveAuthority, 0,
         static_cast<std::uint16_t>(
             observer_v4_family_bit(
                 ObserverV4Family::NarrowS14MpcRealization) |
             observer_v4_family_bit(
                 ObserverV4Family::S12AggregateGroth16))},
        {ObserverV4Family::CounterfactualFullW1Close,
         ObserverV4RequirementMode::AtomicSameInstance,
         ObserverV4Applicability::MissingLiveAuthority, 0, 0},
        {ObserverV4Family::AllFreshTrialHistoryDirectEmpirical,
         ObserverV4RequirementMode::ExhaustiveFreshTrialHistory,
         ObserverV4Applicability::MissingLiveAuthority, 0, 0},
        {ObserverV4Family::SourceRuntimeFreshness,
         ObserverV4RequirementMode::SourceRuntimeFreshness,
         ObserverV4Applicability::MissingLiveAuthority, 0, 0},
    }};

inline constexpr Digest OBSERVER_V4_REGISTRY_IDENTITY = output_abi_digest(
    "0461bd691a26fd78de5df03d48b1cbb2aa57f13625b3d7212c6f064ff60caa92");
inline constexpr Digest OBSERVER_V4_MODEL_IDENTITY = output_abi_digest(
    "ca2328efdc5b4508f57cb37b4d223e520f476dd747720bd2c2691f02ca930162");
inline constexpr Digest OBSERVER_V4_SECTION_IDENTITY = output_abi_digest(
    "486382aea87857ef93938430a0fa31d02d3604113654e5cf98703b8aa6e47948");

inline constexpr std::array<Digest, 4> OBSERVER_V4_S4_IDENTITIES{{
    output_abi_digest("ccd4e28a728cbf8ffd6db0dd0fa81a6200c0c6e4ecb20242435f00e5b6aae19e"),
    output_abi_digest("d8e94558a7b9e3a5cc6187a894cb7f141d85d3c6d862b6a628561a24c4bfdd31"),
    output_abi_digest("1c2d02992ae89810b8a95ede7bf38aefd503f4984e7b82b27db452141752339a"),
    output_abi_digest("8d5738e3726611b07bedec944dc26d8458b728a7d18c1fecf2ad6638aa1cd119"),
}};
// Historical setup provenance, current source closure, the exact
// current-to-historical matrix-equivalence receipt, then matrix/key/verifier
// identities.  c1805c... is the independent verifier, not source or setup.
inline constexpr std::array<Digest, 8> OBSERVER_V4_S12_IDENTITIES{{
    output_abi_digest("3ff31adfc6f2666ac53606ecf60336366d850951fda22a38b7445262f380d829"),
    output_abi_digest("04adfd77d3b97f60efe6c4547cda583856ea7f7be4c9538f4237330ac137a9d7"),
    output_abi_digest("52ca327ac2d3dd2921c0aa913060f8a97f127d81c5d125c1892dc989853ac692"),
    output_abi_digest("c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab"),
    output_abi_digest("170431eee45f57ff6a3dc278d96f8a824145b8ca9ded04088a662983a449e945"),
    output_abi_digest("4a3d0ac3143ecc32a875af8107c923b851036363a68a8a744b97c74d0a3879ff"),
    output_abi_digest("2ca01e24f64b764e0470e67ff4fe183ed9e6d4a2d0b17e77887499c7ed0de102"),
    output_abi_digest("c1805cfe7ae9b2db7d58fd58727b57e92a0fec866506cd720fbd59242359131f"),
}};
inline constexpr Digest OBSERVER_V4_S5_EXECUTABLE_IDENTITY =
    output_abi_digest(
        "6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff");

inline constexpr MeasurementOutputAbiDescriptor OBSERVER_OUTPUT_ABI_V4{
    .role = RuntimeChildRole::Observer,
    .version = 4,
    .magic = {'K', 'P', 'B', 'O', 'A', 'B', 'I', '4'},
    .identity = output_abi_digest(
        "a20ca920eac2f029b02dd1c02fc92dd5108ab7489734ef67000be062be75e200"),
    .used_bytes = OBSERVER_V4_USED_BYTES,
    .exact_bytes = OBSERVER_V4_EXACT_BYTES,
};

bool validate_observer_v4_section(std::span<const unsigned char>);
bool validate_observer_output_v4(std::span<const unsigned char>);

#ifdef KPB_MEASUREMENT_OUTPUT_ABI_V4_TEST_SETUP
std::vector<unsigned char> test_only_observer_output_v4_body();
#endif

struct ObserverV4OutputSourceStatus {
    bool fixed_registry_and_layout{};
    bool v3_prefix_immutable{};
    bool historical_local_s4_s12_eligible{};
    bool all_live_applicability_identities_present{};
    bool serialized_body_is_authority{};
    bool live_family_authority_join{};
    bool all_fresh_trial_ledger_join{};
    bool source_runtime_freshness_join{};
    bool selected_worker{};
    bool configured{};
};

inline constexpr ObserverV4OutputSourceStatus kObserverV4OutputSourceStatus{
    .fixed_registry_and_layout = true,
    .v3_prefix_immutable = true,
    .historical_local_s4_s12_eligible = false,
    .all_live_applicability_identities_present = false,
};

} // namespace kpb::measurement::runtime_bridge
