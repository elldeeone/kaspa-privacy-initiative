#include "fresh_owner_arm_isolation.hpp"

#include <openssl/crypto.h>

#include <array>
#include <cstdint>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::fresh_owner_issuance {
namespace {

using Bytes = std::vector<unsigned char>;

[[noreturn]] void refuse() { throw identity_registry::Refused(); }

template<class Value>
bool zero_bytes(const Value& value) {
    static_assert(std::is_trivially_copyable_v<Value>);
    const auto bytes = std::as_bytes(std::span(&value, 1));
    unsigned aggregate = 0;
    for (const auto byte : bytes)
        aggregate |= std::to_integer<unsigned char>(byte);
    return aggregate == 0;
}

template<class Value>
bool same_bytes(const Value& left, const Value& right) {
    static_assert(std::is_trivially_copyable_v<Value>);
    const auto left_bytes = std::as_bytes(std::span(&left, 1));
    const auto right_bytes = std::as_bytes(std::span(&right, 1));
    unsigned difference = 0;
    for (std::size_t index = 0; index < left_bytes.size(); ++index)
        difference |= std::to_integer<unsigned char>(left_bytes[index]) ^
            std::to_integer<unsigned char>(right_bytes[index]);
    return difference == 0;
}

template<class Value, std::size_t Left, std::size_t Right>
bool disjoint(
        const std::array<Value, Left>& left,
        const std::array<Value, Right>& right) {
    bool result = true;
    for (const auto& left_value : left)
        for (const auto& right_value : right)
            result &= !same_bytes(left_value, right_value);
    return result;
}

template<class Value, std::size_t Size>
bool unique_nonzero(const std::array<Value, Size>& values) {
    bool result = true;
    for (std::size_t left = 0; left < values.size(); ++left) {
        result &= !zero_bytes(values[left]);
        for (std::size_t right = left + 1; right < values.size(); ++right)
            result &= !same_bytes(values[left], values[right]);
    }
    return result;
}

bool valid_pids(const std::array<std::int64_t, 3>& values) {
    bool result = true;
    for (std::size_t left = 0; left < values.size(); ++left) {
        result &= values[left] > 1;
        for (std::size_t right = left + 1; right < values.size(); ++right)
            result &= values[left] != values[right];
    }
    return result;
}

bool pids_disjoint(
        const std::array<std::int64_t, 3>& left,
        const std::array<std::int64_t, 3>& right) {
    bool result = true;
    for (const auto left_value : left)
        for (const auto right_value : right)
            result &= left_value != right_value;
    return result;
}

using RootSlot = std::array<std::uint64_t, 2>;

bool valid_roots(const std::array<RootSlot, 3>& values) {
    bool result = true;
    for (std::size_t left = 0; left < values.size(); ++left) {
        result &= values[left][0] != 0 && values[left][1] != 0;
        for (std::size_t right = left + 1; right < values.size(); ++right)
            result &= values[left] != values[right];
    }
    return result;
}

bool roots_disjoint(
        const std::array<RootSlot, 3>& left,
        const std::array<RootSlot, 3>& right) {
    bool result = true;
    for (const auto& left_value : left)
        for (const auto& right_value : right)
            result &= left_value != right_value;
    return result;
}

std::array<Digest, 18> flatten(
        const std::array<std::array<Digest, 3>, 6>& values) {
    std::array<Digest, 18> result{};
    std::size_t at = 0;
    for (const auto& slot : values)
        for (const auto& value : slot)
            result[at++] = value;
    return result;
}

bool valid_server_tls(
        const std::array<std::array<Digest, 3>, 6>& values) {
    bool result = true;
    for (const auto& slot : values) {
        for (const auto& value : slot) result &= !zero_bytes(value);
        result &= !same_bytes(slot[0], slot[1]);
        result &= !same_bytes(slot[0], slot[2]);
        result &= !same_bytes(slot[1], slot[2]);
    }
    // One authenticated three-server roster per round, repeated across the
    // three owner contracts. The two rounds must use distinct TLS material.
    for (unsigned owner = 1; owner < 3; ++owner) {
        result &= values[owner] == values[0];
        result &= values[3 + owner] == values[3];
    }
    result &= disjoint(values[0], values[3]);
    return result;
}

template<class Evidence>
bool valid_arm(const Evidence& value) {
    bool result = true;
    result &= !zero_bytes(value.process_authority_identity);
    result &= !zero_bytes(value.supervisor_session_identity);
    result &= !same_bytes(
        value.process_authority_identity,
        value.supervisor_session_identity);
    result &= valid_pids(value.child_pids);
    result &= unique_nonzero(value.child_sessions);
    result &= valid_roots(value.root_slots);
    result &= unique_nonzero(value.logical_owner_ids);
    result &= unique_nonzero(value.contract_ids);
    result &= unique_nonzero(value.owner_tls_cert_ids);
    result &= unique_nonzero(value.owner_tls_spki_ids);
    result &= valid_server_tls(value.server_tls_cert_ids);
    result &= valid_server_tls(value.server_tls_spki_ids);
    return result;
}

template<class Evidence>
bool cross_arm_disjoint(const Evidence& baseline, const Evidence& hidden) {
    bool result = true;
    result &= !same_bytes(
        baseline.process_authority_identity,
        hidden.process_authority_identity);
    result &= !same_bytes(
        baseline.supervisor_session_identity,
        hidden.supervisor_session_identity);
    result &= pids_disjoint(baseline.child_pids, hidden.child_pids);
    result &= disjoint(baseline.child_sessions, hidden.child_sessions);
    result &= roots_disjoint(baseline.root_slots, hidden.root_slots);
    result &= disjoint(
        baseline.logical_owner_ids, hidden.logical_owner_ids);
    result &= disjoint(baseline.contract_ids, hidden.contract_ids);
    result &= disjoint(
        baseline.owner_tls_cert_ids, hidden.owner_tls_cert_ids);
    result &= disjoint(
        baseline.owner_tls_spki_ids, hidden.owner_tls_spki_ids);
    result &= disjoint(
        flatten(baseline.server_tls_cert_ids),
        flatten(hidden.server_tls_cert_ids));
    result &= disjoint(
        flatten(baseline.server_tls_spki_ids),
        flatten(hidden.server_tls_spki_ids));
    return result;
}

void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}

void add(Bytes& out, std::string_view value) {
    add(out, std::span(
        reinterpret_cast<const unsigned char*>(value.data()), value.size()));
}

template<class Value>
void add_value(Bytes& out, const Value& value) {
    static_assert(std::is_trivially_copyable_v<Value>);
    const auto bytes = std::as_bytes(std::span(&value, 1));
    add(out, std::span(
        reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()));
}

template<class Evidence>
void add_arm(Bytes& out, const Evidence& value) {
    out.push_back(static_cast<unsigned char>(value.classification));
    add_value(out, value.process_authority_identity);
    add_value(out, value.supervisor_session_identity);
    for (const auto pid : value.child_pids) add_value(out, pid);
    for (const auto& item : value.child_sessions) add_value(out, item);
    for (const auto& item : value.root_slots) {
        add_value(out, item[0]);
        add_value(out, item[1]);
    }
    for (const auto& item : value.logical_owner_ids) add_value(out, item);
    for (const auto& item : value.contract_ids) add_value(out, item);
    for (const auto& item : value.owner_tls_cert_ids) add_value(out, item);
    for (const auto& item : value.owner_tls_spki_ids) add_value(out, item);
    for (const auto& slot : value.server_tls_cert_ids)
        for (const auto& item : slot) add_value(out, item);
    for (const auto& slot : value.server_tls_spki_ids)
        for (const auto& item : slot) add_value(out, item);
}

template<class Evidence>
Digest isolation_identity(
        const Evidence& baseline, const Evidence& hidden) {
    Bytes bytes;
    add(bytes, "KPB_FRESH_OWNER_ARM_ISOLATION_V1\n");
    add_arm(bytes, baseline);
    add_arm(bytes, hidden);
    return identity_registry::digest(bytes);
}

template<class Evidence>
void scrub(Evidence& evidence) noexcept {
    static_assert(std::is_trivially_copyable_v<Evidence>);
    OPENSSL_cleanse(&evidence, sizeof(evidence));
}

} // namespace

FreshOwnerArmIsolationAuthority::FreshOwnerArmIsolationAuthority(
        Digest identity,
        FreshOwnerArmIsolationResidualAuthority&& baseline,
        FreshOwnerArmIsolationResidualAuthority&& hidden_candidate)
    : isolation_authority_identity_(identity) {
    if (zero_bytes(identity)) refuse();
    baseline_.emplace(std::move(baseline));
    hidden_candidate_.emplace(std::move(hidden_candidate));
}

FreshOwnerArmIsolationAuthority::FreshOwnerArmIsolationAuthority(
        FreshOwnerArmIsolationAuthority&& other) noexcept {
    std::lock_guard guard(other.mutex_);
    isolation_authority_identity_ = other.isolation_authority_identity_;
    if (other.baseline_) {
        baseline_.emplace(std::move(*other.baseline_));
        other.baseline_.reset();
    }
    if (other.hidden_candidate_) {
        hidden_candidate_.emplace(std::move(*other.hidden_candidate_));
        other.hidden_candidate_.reset();
    }
    live_.store(other.live_.exchange(false));
    OPENSSL_cleanse(
        other.isolation_authority_identity_.data(),
        other.isolation_authority_identity_.size());
}

FreshOwnerArmIsolationAuthority::~FreshOwnerArmIsolationAuthority() {
    OPENSSL_cleanse(
        isolation_authority_identity_.data(),
        isolation_authority_identity_.size());
}

FreshOwnerArmIsolationResidualAuthority
FreshOwnerArmIsolationAuthority::take_baseline_residual() {
    std::lock_guard guard(mutex_);
    if (!live_.load() || !baseline_) refuse();
    FreshOwnerArmIsolationResidualAuthority result(
        std::move(*baseline_));
    baseline_.reset();
    if (!hidden_candidate_) live_ = false;
    return result;
}

FreshOwnerArmIsolationResidualAuthority
FreshOwnerArmIsolationAuthority::take_hidden_candidate_residual() {
    std::lock_guard guard(mutex_);
    if (!live_.load() || !hidden_candidate_) refuse();
    FreshOwnerArmIsolationResidualAuthority result(
        std::move(*hidden_candidate_));
    hidden_candidate_.reset();
    if (!baseline_) live_ = false;
    return result;
}

FreshOwnerArmIsolationAuthority FreshOwnerArmIsolationBridge::join(
        FreshOwnerPrivateArmLaunchAuthority&& baseline,
        FreshOwnerPrivateArmLaunchAuthority&& hidden_candidate) {
    const bool baseline_live = baseline.live_.exchange(false);
    const bool hidden_live = hidden_candidate.live_.exchange(false);
    try {
        const auto baseline_classification = baseline.evidence_.classification;
        const auto hidden_classification =
            hidden_candidate.evidence_.classification;
        const auto baseline_process =
            baseline.evidence_.process_authority_identity;
        const auto hidden_process =
            hidden_candidate.evidence_.process_authority_identity;
        const auto baseline_supervisor =
            baseline.evidence_.supervisor_session_identity;
        const auto hidden_supervisor =
            hidden_candidate.evidence_.supervisor_session_identity;

        bool accepted = baseline_live & hidden_live;
        accepted &= baseline_classification ==
            registered_driver::CaptureClassification::
                ExplicitOwnerPublicEffectsBaseline;
        accepted &= hidden_classification ==
            registered_driver::CaptureClassification::HiddenCandidate;
        accepted &= valid_arm(baseline.evidence_);
        accepted &= valid_arm(hidden_candidate.evidence_);
        accepted &= cross_arm_disjoint(
            baseline.evidence_, hidden_candidate.evidence_);
        const auto identity = isolation_identity(
            baseline.evidence_, hidden_candidate.evidence_);
        accepted &= !zero_bytes(identity);

        scrub(baseline.evidence_);
        scrub(hidden_candidate.evidence_);
        if (!accepted) refuse();

        return FreshOwnerArmIsolationAuthority(
            identity,
            FreshOwnerArmIsolationResidualAuthority(
                baseline_classification, identity,
                baseline_process, baseline_supervisor),
            FreshOwnerArmIsolationResidualAuthority(
                hidden_classification, identity,
                hidden_process, hidden_supervisor));
    } catch (...) {
        scrub(baseline.evidence_);
        scrub(hidden_candidate.evidence_);
        refuse();
    }
}

FreshOwnerArmIsolationSourceStatus
fresh_owner_arm_isolation_source_status() {
    return {
        .schema = "kpi-fresh-owner-arm-isolation-source-status/v1",
        .status = "SOURCE_ONLY_CONFIGURED0",
        .exact_baseline_hidden_pair = true,
        .full_cross_set_private_disjointness = true,
        .mandatory_r1_residual_gate = true,
        .role_permutation_shortcut = false,
        .public_or_durable_raw_identifier_output = false,
        .production_paired_trial_callsite = false,
        .registered_driver_configured = false,
        .launch_authorized = false,
    };
}

} // namespace kpi::mpc::financial::fresh_owner_issuance
