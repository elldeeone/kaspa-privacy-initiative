#pragma once

// ADR-0077 local durability primitive. Its receipts attest local writes only;
// they are NOT owner-intake, proof, publication or settlement capabilities.
// The financial bridge additionally performs authenticated all-three agreement.
#include <array>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace kpi::mpc::history {
using Digest = std::array<unsigned char, 32>;
using Point = std::array<unsigned char, 36>;
using State = std::array<unsigned char, 112>;
using ScriptPublicKey = std::array<unsigned char, 37>;

class Refused final : public std::runtime_error {
public:
    Refused() : std::runtime_error("private batch continuation refused") {}
};

Digest digest(std::span<const unsigned char>);
Digest unhex(const std::string&);
std::string hex(const Digest&);

struct EpochKey {
    Digest chain, pool, domain, profile, service, epoch;
    std::array<Digest, 3> server_certificates;
    bool operator==(const EpochKey&) const = default;
};

struct AttemptBinding {
    Digest attempt, cohort, owner_contracts;
    Digest model, source, dependencies, matrix, trace, layout, input_map;
    Digest prefix_recipe, validation_policy, admitted_head;
    Point old_point;
    State old_state;
    uint64_t old_reserve;
    ScriptPublicKey old_spk{};
    Digest immutable_tail{}, native_parameters{};
    bool operator==(const AttemptBinding&) const = default;
};

struct EgressPacket {
    Digest effects, core, aggregate_proof, projection;
    // Canonical lexicographically sorted set; never an owner-labelled map.
    std::array<Digest, 3> nullifiers;
    bool operator==(const EgressPacket&) const = default;
};

struct FinalCandidate {
    Digest raw_case, canonical_case, projection, selection;
    Digest image, journal, outer_receipt, native_proof;
    bool operator==(const FinalCandidate&) const = default;
};

enum class Phase : uint8_t {
    Ready = 0, Locked = 1, Prepared = 2, Egress = 3, FinalCandidate = 4,
    ExposureConflict = 5
};
enum class WriteBoundary { JournalWritten, JournalSynced, AnchorWritten, AnchorSynced };
using FailureOnlyHook = std::function<void(WriteBoundary)>;

struct PublicSnapshot {
    EpochKey key;
    uint64_t sequence;
    Digest checkpoint;
    Phase phase;
    std::optional<AttemptBinding> attempt;
    std::optional<Digest> effects;
    std::optional<EgressPacket> egress;
    std::optional<FinalCandidate> candidate;
    std::vector<Digest> seen_nullifiers;
    Digest seen_identity;
};

namespace detail { struct JournalCore; }
class EpochJournal;
class LockedAttempt;
class PreparedEpochTicket;

// Public metadata from a completed LOCAL durable append. A peer agreement or
// a real financial proof ticket cannot be manufactured from this class alone.
class DurableRecord {
    const std::shared_ptr<detail::JournalCore> core_;
    const uint64_t sequence_;
    const Digest checkpoint_;
    const Phase phase_;
    DurableRecord(std::shared_ptr<detail::JournalCore>, uint64_t, Digest, Phase);
    friend class EpochJournal;
    friend class LockedAttempt;
    friend class PreparedEpochTicket;
    friend struct detail::JournalCore;
public:
    uint64_t sequence() const { return sequence_; }
    const Digest& checkpoint() const { return checkpoint_; }
    Phase phase() const { return phase_; }
};

class EpochJournal {
    std::shared_ptr<detail::JournalCore> core_;
    explicit EpochJournal(std::shared_ptr<detail::JournalCore>);
    friend class LockedAttempt;
    friend class PreparedEpochTicket;
public:
    EpochJournal(const EpochJournal&) = delete;
    EpochJournal(EpochJournal&&) = delete;
    EpochJournal& operator=(const EpochJournal&) = delete;
    EpochJournal& operator=(EpochJournal&&) = delete;

    // Trusted one-time bootstrap only, before any funding or owner intake.
    // Production financial drivers must expose only open_existing. A missing
    // journal/anchor is NEVER an instruction to call this method. It accepts
    // only fresh empty directories and never overwrites/reinitializes a key.
#ifdef KPI_HISTORY_UNFUNDED_SETUP
    static EpochJournal initialize_fresh_unfunded(
        const std::filesystem::path& local_directory,
        const std::filesystem::path& trusted_anchor_directory,
        const EpochKey&, const Digest& authenticated_registration);
#endif
    static EpochJournal open_existing(
        const std::filesystem::path& local_directory,
        const std::filesystem::path& trusted_anchor_directory,
        const EpochKey&, const Digest& authenticated_registration);

    PublicSnapshot snapshot() const;
    DurableRecord lock(const AttemptBinding&, FailureOnlyHook = {});
    DurableRecord prepare(const DurableRecord& lock, const Digest& effects,
                          FailureOnlyHook = {});
    DurableRecord record_egress(const DurableRecord& prepared, const EgressPacket&,
                                FailureOnlyHook = {});
    DurableRecord bind_final_candidate(const DurableRecord& egress,
                                      const FinalCandidate&, FailureOnlyHook = {});

    // There is deliberately NO public resolve(bool), accept(txid), reset,
    // cancel, timeout, Exit or reorg operation. Verified settlement integration
    // must supply a separately reviewed, implementation-private capability.
};

std::vector<unsigned char> encode(const EpochKey&);
std::vector<unsigned char> encode(const AttemptBinding&);
std::vector<unsigned char> encode(const EgressPacket&);
std::vector<unsigned char> encode(const FinalCandidate&);
Digest binding_identity(const EpochKey&, const AttemptBinding&);
// Financial wire NF rows are numeric little-endian ordered. The permanent
// history SET is bytewise ordered; this pure public conversion mutates neither
// the core nor its projection and grants no proof/release authority.
std::array<Digest, 3> canonical_history_nullifiers(
    std::span<const unsigned char> actual_core10364);
// Established BLAKE2b-256 P2SH over PUSHDATA1(112)||State112||immutable tail.
// Implemented with the already selected libsodium dependency, never by
// truncating BLAKE2b-512. No financial proof/acceptance is implied.
ScriptPublicKey reserve_spk(const State&, std::span<const unsigned char> tail);
}  // namespace kpi::mpc::history
