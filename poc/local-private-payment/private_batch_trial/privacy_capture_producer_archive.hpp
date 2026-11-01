#pragma once

// Exact raw-wire retention owned by the sole C++ capture reader. The builder
// is production-constructible only by ParentOwnedCaptureProducer; possession
// of a builder permits checked append and one ordered END+EOF writer-closure
// transition per slot. Storage is anonymous disk-backed O_TMPFILE; this is
// deliberately not a kernel F_SEAL claim.

#include "privacy_capture_producer_runtime.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <span>

namespace kpb::measurement::producer_archive {

inline constexpr unsigned PRODUCER_ARCHIVE_STREAM_COUNT = 10;

class ProducerSealedArchiveAuthority;
class ProducerArchiveObserverTransfer;
class ProducerPartialC03ArchiveAuthority;
class ProducerPartialC03ArchiveRuntimeTransfer;
class ProducerArchiveQuarantineAuthority;

// Private source-owned reason for retaining the unsealed parent files.  The
// enum is diagnostic shape only; no public accessor can turn it into outcome
// authority or expose a descriptor/body/hash.
enum class ProducerArchiveQuarantineStage : unsigned char {
    Append = 1,
    FullSeal = 2,
    PartialC03Seal = 3,
    Inspection = 4,
    Transport = 5,
    Internal = 6,
};

class ProducerSealedArchiveBuilder final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    ProducerSealedArchiveBuilder(RunBinding, Digest closure_identity);
    explicit ProducerSealedArchiveBuilder(std::unique_ptr<Storage>);
    static ProducerSealedArchiveBuilder adopt_preidentity_reservation(
        RunBinding, Digest closure_identity, Digest reservation_identity,
        std::array<int, PRODUCER_ARCHIVE_STREAM_COUNT>&& archive_fds,
        const std::array<std::uint64_t,
                         PRODUCER_ARCHIVE_STREAM_COUNT>& devices,
        const std::array<std::uint64_t,
                         PRODUCER_ARCHIVE_STREAM_COUNT>& inodes,
        const std::array<std::uint32_t,
                         PRODUCER_ARCHIVE_STREAM_COUNT>& modes,
        const std::array<std::uint64_t,
                         PRODUCER_ARCHIVE_STREAM_COUNT>& nlinks,
        const std::array<std::uint64_t,
                         PRODUCER_ARCHIVE_STREAM_COUNT>& sizes);
    ProducerPartialC03ArchiveAuthority seal_partial_c03_for_runtime() &&;
    ProducerArchiveQuarantineAuthority quarantine_for_runtime(
        ProducerArchiveQuarantineStage, int error_number) && noexcept;
    std::array<int, PRODUCER_ARCHIVE_STREAM_COUNT>
        inherited_writer_fds_for_runtime() const;
    friend class producer_runtime::ParentOwnedCaptureProducer;
    friend class ProducerArchiveQuarantineAuthority;
    friend class kpi::mpc::financial::registered_driver::
        RegisteredFreshTrialProducerClosureBridge;
public:
    ProducerSealedArchiveBuilder(
        const ProducerSealedArchiveBuilder&) = delete;
    ProducerSealedArchiveBuilder& operator=(
        const ProducerSealedArchiveBuilder&) = delete;
    ProducerSealedArchiveBuilder(ProducerSealedArchiveBuilder&&) noexcept;
    ProducerSealedArchiveBuilder& operator=(
        ProducerSealedArchiveBuilder&&) = delete;
    ~ProducerSealedArchiveBuilder();

    void append(unsigned slot, std::span<const unsigned char>);
    void finish_after_end_and_eof(
        unsigned slot, const ProducerStreamClosureEvidence&);
    ProducerSealedArchiveAuthority finish() &&;
#ifdef KPB_CAPTURE_PRODUCER_ARCHIVE_TEST_SETUP
    static ProducerSealedArchiveBuilder test_only_begin(
        RunBinding, Digest closure_identity);
    static std::array<int, PRODUCER_ARCHIVE_STREAM_COUNT>
        test_only_inherited_writer_fds(
            const ProducerSealedArchiveBuilder&);
    static ProducerPartialC03ArchiveAuthority test_only_seal_partial_c03(
        ProducerSealedArchiveBuilder&&);
    static void test_only_fail_partial_after_first_transition(
        ProducerSealedArchiveBuilder&);
    static ProducerArchiveQuarantineAuthority test_only_quarantine(
        ProducerSealedArchiveBuilder&&,
        ProducerArchiveQuarantineStage, int error_number) noexcept;
#endif
};

// Live-process linear owner of the exact parent-retained anonymous files after
// a sealing, inspection or transport failure. It deliberately makes no claim
// that the files are allocation-failure durable, crash durable, sealed,
// parsed, complete, read-only or hash-validated. Only the complete producer
// runtime may consume it into the future typed unavailable outcome; callers
// cannot inspect or reconstruct it.
class ProducerArchiveQuarantineAuthority final {
    std::unique_ptr<ProducerSealedArchiveBuilder::Storage> storage_;
    ProducerArchiveQuarantineStage stage_{};
    int error_number_{};
    ProducerArchiveQuarantineAuthority(
        std::unique_ptr<ProducerSealedArchiveBuilder::Storage>,
        ProducerArchiveQuarantineStage, int) noexcept;
    friend class ProducerSealedArchiveBuilder;
    friend class producer_runtime::ParentOwnedCaptureProducer;
public:
    ProducerArchiveQuarantineAuthority(
        const ProducerArchiveQuarantineAuthority&) = delete;
    ProducerArchiveQuarantineAuthority& operator=(
        const ProducerArchiveQuarantineAuthority&) = delete;
    ProducerArchiveQuarantineAuthority(
        ProducerArchiveQuarantineAuthority&&) noexcept;
    ProducerArchiveQuarantineAuthority& operator=(
        ProducerArchiveQuarantineAuthority&&) = delete;
    ~ProducerArchiveQuarantineAuthority();
#ifdef KPB_CAPTURE_PRODUCER_ARCHIVE_TEST_SETUP
    struct TestOnlySummary {
        RunBinding binding;
        Digest closure_identity{};
        Digest reservation_identity{};
        ProducerArchiveQuarantineStage stage{};
        int error_number{};
        std::array<bool, PRODUCER_ARCHIVE_STREAM_COUNT>
            descriptor_retained{};
        std::array<std::uint64_t, PRODUCER_ARCHIVE_STREAM_COUNT> devices{};
        std::array<std::uint64_t, PRODUCER_ARCHIVE_STREAM_COUNT> inodes{};
        std::array<std::uint64_t, PRODUCER_ARCHIVE_STREAM_COUNT> sizes{};
        std::array<int, PRODUCER_ARCHIVE_STREAM_COUNT> access_modes{};
        std::array<bool, PRODUCER_ARCHIVE_STREAM_COUNT> finished{};
    };
    TestOnlySummary test_only_summary() const;
#endif
};

// Private two-slot failure archive. It can only be created from the live
// sole-reader builder and only the complete ParentOwnedCaptureProducer may
// transport/adopt it. No descriptor, hash, count, or receipt is public.
class ProducerPartialC03ArchiveAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit ProducerPartialC03ArchiveAuthority(std::unique_ptr<Storage>);
    ProducerPartialC03ArchiveRuntimeTransfer
        duplicate_for_runtime_transport() &&;
    static ProducerPartialC03ArchiveAuthority adopt_runtime_transport(
        ProducerPartialC03ArchiveRuntimeTransfer&&);
    friend class ProducerSealedArchiveBuilder;
    friend class ProducerSealedArchiveAuthority;
    friend class producer_runtime::ParentOwnedCaptureProducer;
public:
    ProducerPartialC03ArchiveAuthority(
        const ProducerPartialC03ArchiveAuthority&) = delete;
    ProducerPartialC03ArchiveAuthority& operator=(
        const ProducerPartialC03ArchiveAuthority&) = delete;
    ProducerPartialC03ArchiveAuthority(
        ProducerPartialC03ArchiveAuthority&&) noexcept;
    ProducerPartialC03ArchiveAuthority& operator=(
        ProducerPartialC03ArchiveAuthority&&) = delete;
    ~ProducerPartialC03ArchiveAuthority();
#ifdef KPB_CAPTURE_PRODUCER_ARCHIVE_TEST_SETUP
    enum class TestOnlyTransportFault : unsigned char {
        None,
        MissingFd,
        WritableFd,
        DuplicateInode,
        WrongSourceSlot,
        WrongSize,
        WrongHash,
        FalseComplete,
    };
    struct TestOnlySummary {
        RunBinding binding;
        Digest closure_identity{};
        Digest reservation_identity{};
        std::array<unsigned, 2> source_slots{};
        std::array<unsigned, 2> fixed_fds{};
        std::array<std::uint64_t, 2> devices{};
        std::array<std::uint64_t, 2> inodes{};
        std::array<std::uint64_t, 2> sizes{};
        std::array<int, 2> seals{};
        std::array<bool, 2> read_only{};
        std::array<bool, 2> writer_aliases_closed{};
        std::array<Digest, 2> sha256{};
        std::array<bool, 2> complete_end_and_eof{};
    };
    TestOnlySummary test_only_summary() const;
    ProducerPartialC03ArchiveAuthority
        test_only_transport_roundtrip(
            TestOnlyTransportFault = TestOnlyTransportFault::None) &&;
#endif
};

// Fully defined, opaque runtime-only handoff. The complete producer runtime is
// the sole non-test reader of its private fields and descriptor array.
class ProducerPartialC03ArchiveRuntimeTransfer final {
    RunBinding binding_;
    Digest closure_identity_{};
    Digest reservation_identity_{};
    std::array<unsigned, 2> source_slots_{};
    std::array<unsigned, 2> fixed_fds_{};
    std::array<int, 2> fds_{};
    std::array<std::uint64_t, 2> devices_{};
    std::array<std::uint64_t, 2> inodes_{};
    std::array<std::uint64_t, 2> sizes_{};
    std::array<int, 2> seals_{};
    std::array<Digest, 2> sha256_{};
    std::array<bool, 2> complete_end_and_eof_{};
    std::array<ProducerStreamClosureEvidence, 2> evidence_{};
    ProducerPartialC03ArchiveRuntimeTransfer();
    friend class ProducerPartialC03ArchiveAuthority;
    friend class producer_runtime::ParentOwnedCaptureProducer;
public:
    ProducerPartialC03ArchiveRuntimeTransfer(
        const ProducerPartialC03ArchiveRuntimeTransfer&) = delete;
    ProducerPartialC03ArchiveRuntimeTransfer& operator=(
        const ProducerPartialC03ArchiveRuntimeTransfer&) = delete;
    ProducerPartialC03ArchiveRuntimeTransfer(
        ProducerPartialC03ArchiveRuntimeTransfer&&) noexcept;
    ProducerPartialC03ArchiveRuntimeTransfer& operator=(
        ProducerPartialC03ArchiveRuntimeTransfer&&) = delete;
    ~ProducerPartialC03ArchiveRuntimeTransfer();
};

class ProducerSealedArchiveAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit ProducerSealedArchiveAuthority(std::unique_ptr<Storage>);
    std::array<int, PRODUCER_ARCHIVE_STREAM_COUNT>
        duplicate_for_transport() const;
    ProducerPartialC03ArchiveAuthority duplicate_c03_for_runtime() const;
    static ProducerSealedArchiveAuthority adopt_received(
        RunBinding, Digest closure_identity,
        std::array<int, PRODUCER_ARCHIVE_STREAM_COUNT>&&,
        std::array<ProducerStreamClosureEvidence,
                   PRODUCER_ARCHIVE_STREAM_COUNT>);
    ProducerArchiveObserverTransfer consume_for_observer() &&;
    friend class ProducerSealedArchiveBuilder;
    friend class producer_runtime::ParentOwnedCaptureProducer;
    friend class runtime_bridge::ObserverCaptureCapsuleBridge;
public:
    ProducerSealedArchiveAuthority(
        const ProducerSealedArchiveAuthority&) = delete;
    ProducerSealedArchiveAuthority& operator=(
        const ProducerSealedArchiveAuthority&) = delete;
    ProducerSealedArchiveAuthority(
        ProducerSealedArchiveAuthority&&) noexcept;
    ProducerSealedArchiveAuthority& operator=(
        ProducerSealedArchiveAuthority&&) = delete;
    ~ProducerSealedArchiveAuthority();
#ifdef KPB_CAPTURE_PRODUCER_ARCHIVE_TEST_SETUP
    std::array<int, PRODUCER_ARCHIVE_STREAM_COUNT>
        test_only_duplicate_transport_fds() const;
    static ProducerSealedArchiveAuthority test_only_adopt_received(
        RunBinding, Digest closure_identity,
        std::array<int, PRODUCER_ARCHIVE_STREAM_COUNT>&&,
        std::array<ProducerStreamClosureEvidence,
                   PRODUCER_ARCHIVE_STREAM_COUNT>);
    bool test_only_matches(
        const RunBinding&, const Digest& closure_identity,
        const std::array<ProducerStreamClosureEvidence,
                         PRODUCER_ARCHIVE_STREAM_COUNT>&) const;
    ProducerPartialC03ArchiveAuthority
        test_only_duplicate_c03_for_runtime() const;
#endif
};

// Opaque one-shot transfer used only by the fully defined observer bridge.
// It has no descriptor, evidence, receipt, or hash accessor.
class ProducerArchiveObserverTransfer final {
    RunBinding binding_;
    Digest closure_identity_{};
    Digest reservation_identity_{};
    std::array<int, PRODUCER_ARCHIVE_STREAM_COUNT> fds_{};
    std::array<std::uint64_t, PRODUCER_ARCHIVE_STREAM_COUNT> devices_{};
    std::array<std::uint64_t, PRODUCER_ARCHIVE_STREAM_COUNT> inodes_{};
    std::array<std::uint64_t, PRODUCER_ARCHIVE_STREAM_COUNT> sizes_{};
    std::array<ProducerStreamClosureEvidence,
               PRODUCER_ARCHIVE_STREAM_COUNT> evidence_{};
    ProducerArchiveObserverTransfer();
    friend class ProducerSealedArchiveAuthority;
    friend class runtime_bridge::ObserverCaptureCapsuleBridge;
public:
    ProducerArchiveObserverTransfer(
        const ProducerArchiveObserverTransfer&) = delete;
    ProducerArchiveObserverTransfer& operator=(
        const ProducerArchiveObserverTransfer&) = delete;
    ProducerArchiveObserverTransfer(
        ProducerArchiveObserverTransfer&&) noexcept;
    ProducerArchiveObserverTransfer& operator=(
        ProducerArchiveObserverTransfer&&) = delete;
    ~ProducerArchiveObserverTransfer();
};

struct ProducerArchiveSourceStatus {
    bool anonymous_disk_backed_storage{};
    bool live_process_linear_quarantine_owner{};
    bool allocation_failure_no_drop{};
    bool process_crash_durable{};
    bool power_loss_durable{};
    bool writer_alias_closure_seal{};
    bool source_derived_worst_case_bounds{};
    bool prelaunch_disk_reservation{};
    bool typed_archive_failure_invalidation{};
    bool no_drop_quarantine_primitive{};
    bool exact_ten_slot_builder{};
    bool raw_wire_tee{};
    bool seal_after_end_and_eof{};
    bool private_move_only_archive{};
    bool scm_rights_transport{};
    bool parent_adoption_validation{};
    bool partial_c03_failure_archive{};
    bool runtime_drain_integrated{};
    bool observer_admission_integrated{};
    bool configured{};
};

inline constexpr ProducerArchiveSourceStatus kProducerArchiveSourceStatus{
    .anonymous_disk_backed_storage = true,
    .live_process_linear_quarantine_owner = true,
    .allocation_failure_no_drop = false,
    .process_crash_durable = false,
    .power_loss_durable = false,
    .writer_alias_closure_seal = false,
    .source_derived_worst_case_bounds = false,
    .prelaunch_disk_reservation = false,
    .typed_archive_failure_invalidation = false,
    .no_drop_quarantine_primitive = false,
    .exact_ten_slot_builder = true,
    .raw_wire_tee = true,
    .seal_after_end_and_eof = false,
    .private_move_only_archive = true,
    .scm_rights_transport = true,
    .parent_adoption_validation = true,
    .partial_c03_failure_archive = true,
    .runtime_drain_integrated = false,
    .observer_admission_integrated = false,
};

} // namespace kpb::measurement::producer_archive
