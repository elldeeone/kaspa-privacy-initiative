#include "privacy_prelaunch_policy_domain_authority.hpp"

#include "privacy_measurement_sha256.hpp"

#include <algorithm>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace kpb::measurement::prelaunch_policy_domain {
namespace {

// Exact reviewed source pins. The hostile Python control rehashes every named
// file and refuses stale constants. The final build/source closure must still
// bind the compiled objects and transitive dependency graph.
constexpr std::string_view ACCEPTED_HEAD_CPP_SHA256 =
    "6da0b804f210640b58d455e65fbd36a6e06a605e25d08e1544e01e6e3495f2cf";
constexpr std::string_view ACCEPTED_HEAD_HPP_SHA256 =
    "0c44dcd4bc9e21cfe24530f434ca90263dbbd7b5615c7b015d2b6a97fafd1a74";
constexpr std::string_view REGISTERED_SELECTION_CPP_SHA256 =
    "aff77db415e7a58615a7e257e2b60ac32b629c60b929cd19acbffc3ab02f5139";
constexpr std::string_view REGISTERED_SELECTION_HPP_SHA256 =
    "374eb643e29b4c937201ec3dc14d502636461890358f6d79449936cb93c141ea";
constexpr std::string_view FIXED_PUBLIC_RUN_CPP_SHA256 =
    "9172b4ab67818a55f1080e2559a053251df5f19908955cf970ebd5f6989f7a37";
constexpr std::string_view FIXED_PUBLIC_RUN_HPP_SHA256 =
    "1495669a83401b37116e3b8ef5ec6ccd23c3beffb0296529fac73a083a74668a";

constexpr std::string_view ACCEPTED_HEAD_POLICY_DESCRIPTOR =
    "fresh-random-nonce;fixed-registered-acquisition-program;"
    "KPB_ACCEPTED_FINANCIAL_HEAD_V1;KPBHAD01-837;"
    "service-key-registration-native-parameters-tail-bound;"
    "live-output0-reserve-min60000000;commitment-nullifier-ranges;"
    "reserve-script-recomputed;public-agreement-before-return";
constexpr std::string_view SELECTED_MAIN_POLICY_DESCRIPTOR =
    "service-and-model-live;fresh-accepted-head-consumed;"
    "secret-derived-prefix;instances3-witnesses12949818-"
    "constraints13093029-domain16777216;matrix-c02320f8;"
    "three-role-fixed-public-compiler;descriptor-trace-layout-recipes-bound;"
    "native-tail-reserve-script-recomputed;complete-selection-agreement";

[[noreturn]] void refuse() {
    throw std::runtime_error("prelaunch-policy-domain-refused");
}
void need(bool value) { if (!value) refuse(); }
bool nonzero(const PolicyDigest& value) {
    return std::any_of(value.begin(), value.end(),
        [](unsigned char byte) { return byte != 0; });
}
void add(std::vector<unsigned char>& output, std::string_view value) {
    output.insert(output.end(), value.begin(), value.end());
}
void add(std::vector<unsigned char>& output, const PolicyDigest& value) {
    output.insert(output.end(), value.begin(), value.end());
}
PolicyDigest digest(std::string_view domain,
                    std::span<const std::string_view> values) {
    std::vector<unsigned char> bytes(domain.begin(), domain.end());
    for (const auto value : values) {
        need(value.size() <= 0xffff);
        bytes.push_back(static_cast<unsigned char>(value.size()));
        bytes.push_back(static_cast<unsigned char>(value.size() >> 8));
        add(bytes, value);
    }
    const auto result = detail::sha256(std::span<const unsigned char>(bytes));
    need(nonzero(result));
    return result;
}

PolicyDigest accepted_head_policy_identity() {
    const std::array values{
        std::string_view{"mpc-prover/financial/accepted_head.cpp"},
        ACCEPTED_HEAD_CPP_SHA256,
        std::string_view{"mpc-prover/financial/accepted_head.hpp"},
        ACCEPTED_HEAD_HPP_SHA256,
        std::string_view{"mpc-prover/financial/fixed_public_run.cpp"},
        FIXED_PUBLIC_RUN_CPP_SHA256,
        std::string_view{"mpc-prover/financial/fixed_public_run.hpp"},
        FIXED_PUBLIC_RUN_HPP_SHA256,
        ACCEPTED_HEAD_POLICY_DESCRIPTOR,
    };
    return digest("KPB_ACCEPTED_HEAD_POLICY_ALGORITHM_V1\n", values);
}

PolicyDigest selected_main_policy_identity(
        const PolicyDigest& accepted_policy) {
    const std::array values{
        std::string_view{"mpc-prover/financial/registered_selection.cpp"},
        REGISTERED_SELECTION_CPP_SHA256,
        std::string_view{"mpc-prover/financial/registered_selection.hpp"},
        REGISTERED_SELECTION_HPP_SHA256,
        std::string_view{"mpc-prover/financial/fixed_public_run.cpp"},
        FIXED_PUBLIC_RUN_CPP_SHA256,
        std::string_view{"mpc-prover/financial/fixed_public_run.hpp"},
        FIXED_PUBLIC_RUN_HPP_SHA256,
        SELECTED_MAIN_POLICY_DESCRIPTOR,
    };
    auto bytes = std::vector<unsigned char>{};
    const auto source = digest(
        "KPB_SELECTED_MAIN_POLICY_SOURCE_V1\n", values);
    add(bytes, "KPB_SELECTED_MAIN_POLICY_ALGORITHM_V1\n");
    add(bytes, accepted_policy);
    add(bytes, source);
    const auto result = detail::sha256(std::span<const unsigned char>(bytes));
    need(nonzero(result));
    return result;
}

PolicyDigest manifest_identity(const PolicyDigest& accepted,
                               const PolicyDigest& selected) {
    std::vector<unsigned char> bytes;
    add(bytes, "KPB_PRELAUNCH_FINANCIAL_POLICY_MANIFEST_V1\n");
    add(bytes, accepted);
    add(bytes, selected);
    const auto result = detail::sha256(std::span<const unsigned char>(bytes));
    need(nonzero(result) && result != accepted && result != selected &&
         accepted != selected);
    return result;
}

} // namespace

struct RegisteredPrelaunchPolicyDomainAuthority::Storage final {
    PolicyDigest accepted_head_policy_identity{};
    PolicyDigest selected_main_policy_identity{};
    PolicyDigest source_manifest_identity{};
};

RegisteredPrelaunchPolicyDomainAuthority::
RegisteredPrelaunchPolicyDomainAuthority(
        std::unique_ptr<Storage> storage) noexcept
    : storage_(std::move(storage)) {}
RegisteredPrelaunchPolicyDomainAuthority::
RegisteredPrelaunchPolicyDomainAuthority(
        RegisteredPrelaunchPolicyDomainAuthority&&) noexcept = default;
RegisteredPrelaunchPolicyDomainAuthority::
~RegisteredPrelaunchPolicyDomainAuthority() = default;

void RegisteredPrelaunchPolicyDomainAuthority::
consume_for_selected_activation(
        PolicyDigest& accepted_head_policy_identity,
        PolicyDigest& selected_main_policy_identity,
        PolicyDigest& source_manifest_identity) && {
    need(storage_ != nullptr);
    auto storage = std::move(storage_);
    need(nonzero(storage->accepted_head_policy_identity) &&
         nonzero(storage->selected_main_policy_identity) &&
         nonzero(storage->source_manifest_identity) &&
         storage->accepted_head_policy_identity !=
             storage->selected_main_policy_identity &&
         storage->source_manifest_identity !=
             storage->accepted_head_policy_identity &&
         storage->source_manifest_identity !=
             storage->selected_main_policy_identity);
    accepted_head_policy_identity =
        storage->accepted_head_policy_identity;
    selected_main_policy_identity =
        storage->selected_main_policy_identity;
    source_manifest_identity = storage->source_manifest_identity;
}

RegisteredPrelaunchPolicyDomainAuthority
RegisteredPrelaunchPolicyDomainSourceBridge::acquire() {
    const auto accepted = accepted_head_policy_identity();
    const auto selected = selected_main_policy_identity(accepted);
    auto storage = std::make_unique<
        RegisteredPrelaunchPolicyDomainAuthority::Storage>();
    storage->accepted_head_policy_identity = accepted;
    storage->selected_main_policy_identity = selected;
    storage->source_manifest_identity = manifest_identity(accepted, selected);
    return RegisteredPrelaunchPolicyDomainAuthority(std::move(storage));
}

#ifdef KPB_PRELAUNCH_POLICY_DOMAIN_TEST_SETUP
TestOnlyRegisteredPrelaunchPolicyDomainSummary
RegisteredPrelaunchPolicyDomainSourceBridge::test_only_consume(
        RegisteredPrelaunchPolicyDomainAuthority&& supplied) {
    need(supplied.storage_ != nullptr);
    auto storage = std::move(supplied.storage_);
    return {
        .accepted_head_policy_identity =
            storage->accepted_head_policy_identity,
        .selected_main_policy_identity =
            storage->selected_main_policy_identity,
        .source_manifest_identity = storage->source_manifest_identity,
    };
}
#endif

} // namespace kpb::measurement::prelaunch_policy_domain
