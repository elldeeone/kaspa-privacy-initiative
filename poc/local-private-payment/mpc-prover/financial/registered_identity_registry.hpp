#pragma once

// Durable, public-identity-only freshness authority for a future registered
// financial driver. Consuming an identity grants no owner intake, MPC, proof,
// funding, broadcast, settlement, or launch authority.

#include <array>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace kpi::mpc::financial::identity_registry {

using Digest = std::array<unsigned char, 32>;

class Refused final : public std::runtime_error {
public:
    Refused() : std::runtime_error("registered identity freshness refused") {}
};

// These four pins identify the only registration and selected source/build
// closure for which this registry is authoritative. Abort tombstones are part
// of that immutable authority and are never supplied at consume time.
struct Authority {
    Digest registration;
    Digest service;
    Digest source;
    Digest build;
    std::vector<Digest> aborted_runs;
    bool operator==(const Authority&) const = default;
};

// All eight public identities are consumed in one durable event. There is no
// prior-identities or completion-JSON parameter: caller reports are not a
// freshness authority.
struct Selection {
    Digest run;
    Digest trial;
    Digest attempt;
    Digest cohort;
    Digest accepted_head;
    std::array<Digest, 3> owner_contracts;
    bool operator==(const Selection&) const = default;
};

enum class WriteBoundary {
    JournalWritten,
    JournalSynced,
    AnchorWritten,
    AnchorSynced,
};
using FailureOnlyHook = std::function<void(WriteBoundary)>;

struct PublicSnapshot {
    Digest authority_identity;
    std::uint64_t sequence;
    Digest checkpoint;
    Digest consumed_set_identity;
};

struct PublicReceipt {
    Digest authority_identity;
    Digest selection_identity;
    std::uint64_t sequence;
    Digest checkpoint;
    Digest consumed_set_identity;
};

namespace detail { struct RegistryCore; }

// This capability deliberately exposes only hashes over public identities. A
// future private-intake entry point must require this exact non-forgeable type.
class ConsumedIdentity final {
    const std::shared_ptr<detail::RegistryCore> core_;
    const PublicReceipt receipt_;
    ConsumedIdentity(std::shared_ptr<detail::RegistryCore>, PublicReceipt);
    friend class Registry;
public:
    ConsumedIdentity(const ConsumedIdentity&) = delete;
    ConsumedIdentity(ConsumedIdentity&&) = delete;
    ConsumedIdentity& operator=(const ConsumedIdentity&) = delete;
    ConsumedIdentity& operator=(ConsumedIdentity&&) = delete;
    const PublicReceipt& public_receipt() const { return receipt_; }
};

class Registry final {
    std::shared_ptr<detail::RegistryCore> core_;
    explicit Registry(std::shared_ptr<detail::RegistryCore>);
public:
    Registry(const Registry&) = delete;
    Registry(Registry&&) = delete;
    Registry& operator=(const Registry&) = delete;
    Registry& operator=(Registry&&) = delete;

    // Trusted setup surface only. Registered production drivers must expose
    // only open_existing; missing state is never permission to initialize.
#ifdef KPI_REGISTERED_IDENTITY_UNFUNDED_SETUP
    static Registry initialize_fresh_unfunded(
        const std::filesystem::path& journal_directory,
        const std::filesystem::path& trusted_anchor_directory,
        const Authority&);
#endif

    static Registry open_existing(
        const std::filesystem::path& journal_directory,
        const std::filesystem::path& trusted_anchor_directory,
        const Authority&);

    PublicSnapshot snapshot() const;
    ConsumedIdentity consume(const Selection&, FailureOnlyHook = {});
};

struct SourceStatus {
    std::string schema;
    std::string status;
    bool trial03_retrofit_allowed;
    bool trusted_anchor_required;
    bool coordinated_anchor_rollback_in_scope;
    bool direct_accepted_head_integration;
    bool selected_configured_build_integration;
    bool one_shot_private_intake_integration;
    bool registered_driver_configured;
    bool launch_authorized;
};

Digest digest(std::span<const unsigned char>);
Digest unhex(const std::string&);
std::string hex(const Digest&);
Digest mandatory_aborted_run();
Digest authority_identity(const Authority&);
Digest selection_identity(const Selection&);
SourceStatus source_status();

} // namespace kpi::mpc::financial::identity_registry
