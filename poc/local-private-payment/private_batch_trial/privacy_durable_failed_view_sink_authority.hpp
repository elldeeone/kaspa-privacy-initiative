#pragma once

// Isolated filesystem primitive for the future mandatory failed-view sink.
// Production exposes no root/path/fd/hash/body factory.  The macro-only bridge
// exists solely to exercise the crash-retention mechanics while the selected
// root, byte schedule, serializer and all-branch integration remain missing.

#include "privacy_durable_failed_view_sink_contract.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <string>

namespace kpb::measurement::durable_failed_view {

class DurableFailedViewSinkUnavailableAuthority;

class DurableFailedViewSinkReservationAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit DurableFailedViewSinkReservationAuthority(
        std::unique_ptr<Storage>);
#ifdef KPB_DURABLE_FAILED_VIEW_SINK_TEST_SETUP
    friend class DurableFailedViewSinkTestBridge;
#endif
    friend class DurableFailedViewSinkUnavailableAuthority;
public:
    DurableFailedViewSinkReservationAuthority(
        const DurableFailedViewSinkReservationAuthority&) = delete;
    DurableFailedViewSinkReservationAuthority& operator=(
        const DurableFailedViewSinkReservationAuthority&) = delete;
    DurableFailedViewSinkReservationAuthority(
        DurableFailedViewSinkReservationAuthority&&) noexcept;
    DurableFailedViewSinkReservationAuthority& operator=(
        DurableFailedViewSinkReservationAuthority&&) = delete;
    ~DurableFailedViewSinkReservationAuthority();
};

class DurableFailedViewSinkUnavailableAuthority final {
    std::unique_ptr<DurableFailedViewSinkReservationAuthority::Storage>
        storage_;
    unsigned char failure_stage_{};
    int error_number_{};
    DurableFailedViewSinkUnavailableAuthority(
        std::unique_ptr<DurableFailedViewSinkReservationAuthority::Storage>,
        unsigned char failure_stage, int error_number) noexcept;
#ifdef KPB_DURABLE_FAILED_VIEW_SINK_TEST_SETUP
    friend class DurableFailedViewSinkTestBridge;
#endif
public:
    DurableFailedViewSinkUnavailableAuthority(
        const DurableFailedViewSinkUnavailableAuthority&) = delete;
    DurableFailedViewSinkUnavailableAuthority& operator=(
        const DurableFailedViewSinkUnavailableAuthority&) = delete;
    DurableFailedViewSinkUnavailableAuthority(
        DurableFailedViewSinkUnavailableAuthority&&) noexcept;
    DurableFailedViewSinkUnavailableAuthority& operator=(
        DurableFailedViewSinkUnavailableAuthority&&) = delete;
    ~DurableFailedViewSinkUnavailableAuthority();
};

class DurableFailedViewSinkAuthority final {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit DurableFailedViewSinkAuthority(std::unique_ptr<Storage>);
#ifdef KPB_DURABLE_FAILED_VIEW_SINK_TEST_SETUP
    friend class DurableFailedViewSinkTestBridge;
#endif
public:
    DurableFailedViewSinkAuthority(
        const DurableFailedViewSinkAuthority&) = delete;
    DurableFailedViewSinkAuthority& operator=(
        const DurableFailedViewSinkAuthority&) = delete;
    DurableFailedViewSinkAuthority(
        DurableFailedViewSinkAuthority&&) noexcept;
    DurableFailedViewSinkAuthority& operator=(
        DurableFailedViewSinkAuthority&&) = delete;
    ~DurableFailedViewSinkAuthority();
};

struct DurableFailedViewSinkSourceStatus final {
    bool diagnostic_named_sink_primitive{};
    bool diagnostic_preallocated_payload_blocks{};
    bool diagnostic_same_inode_read_only_reopen{};
    bool diagnostic_file_and_directory_fsync{};
    bool diagnostic_partial_survives_process_exit{};
    bool diagnostic_fault_unavailable_retains_inodes{};
    bool source_owned_root{};
    bool source_owned_exact_byte_schedule{};
    bool canonical_failed_view_serializer{};
    bool outer_owner_integration{};
    bool mandatory_sink{};
    bool configured{};
};

inline constexpr DurableFailedViewSinkSourceStatus
    kDurableFailedViewSinkSourceStatus{
        .diagnostic_named_sink_primitive = true,
        .diagnostic_preallocated_payload_blocks = true,
        .diagnostic_same_inode_read_only_reopen = true,
        .diagnostic_file_and_directory_fsync = true,
        .diagnostic_partial_survives_process_exit = true,
        .diagnostic_fault_unavailable_retains_inodes = true,
        .source_owned_root = false,
        .source_owned_exact_byte_schedule = false,
        .canonical_failed_view_serializer = false,
        .outer_owner_integration = false,
        .mandatory_sink = false,
        .configured = false,
    };

#ifdef KPB_DURABLE_FAILED_VIEW_SINK_TEST_SETUP
enum class TestOnlyDurableFailedViewSinkFault : unsigned char {
    Fallocate = 1,
    WriteShort = 2,
    Enospc = 3,
    FsyncPayload = 4,
    FsyncDirectory = 5,
    Reopen = 6,
};

struct TestOnlyDurableFailedViewSinkSummary final {
    bool private_directory{};
    bool payload_named_and_linked{};
    bool marker_named_and_linked{};
    bool payload_read_only{};
    bool marker_read_only{};
    bool same_payload_inode{};
    bool same_marker_inode{};
    bool payload_exact{};
    bool marker_exact{};
    std::uint64_t payload_device{};
    std::uint64_t payload_inode{};
    std::uint64_t marker_device{};
    std::uint64_t marker_inode{};
};

struct TestOnlyDurableFailedViewUnavailableSummary final {
    bool typed_unavailable{};
    bool payload_inode_retained{};
    bool marker_inode_retained{};
    bool distinct_inodes{};
    bool no_success_marker_before_payload_durability{};
    std::uint64_t payload_device{};
    std::uint64_t payload_inode{};
    std::uint64_t marker_device{};
    std::uint64_t marker_inode{};
    std::uint64_t payload_size{};
    std::uint64_t marker_size{};
    TestOnlyDurableFailedViewSinkFault fault{};
    int error_number{};
};

class DurableFailedViewSinkTestBridge final {
    DurableFailedViewSinkTestBridge() = delete;
    static std::unique_ptr<
        DurableFailedViewSinkReservationAuthority::Storage> reserve_storage(
            const std::string& parent_directory,
            std::uint64_t exact_reserved_payload_bytes,
            bool inject_fallocate_failure);
public:
    static DurableFailedViewSinkReservationAuthority reserve(
        const std::string& parent_directory,
        std::uint64_t exact_reserved_payload_bytes);
    static void write_prefix_and_sync(
        DurableFailedViewSinkReservationAuthority&,
        std::span<const unsigned char>);
    static DurableFailedViewSinkAuthority commit(
        DurableFailedViewSinkReservationAuthority&&,
        std::span<const unsigned char>);
    static DurableFailedViewSinkUnavailableAuthority reserve_unavailable(
        const std::string& parent_directory,
        std::uint64_t exact_reserved_payload_bytes,
        TestOnlyDurableFailedViewSinkFault);
    static DurableFailedViewSinkUnavailableAuthority commit_unavailable(
        DurableFailedViewSinkReservationAuthority&&,
        std::span<const unsigned char>,
        TestOnlyDurableFailedViewSinkFault);
    static TestOnlyDurableFailedViewSinkSummary summarize(
        const DurableFailedViewSinkAuthority&,
        std::span<const unsigned char> expected_payload);
    static TestOnlyDurableFailedViewUnavailableSummary summarize_unavailable(
        const DurableFailedViewSinkUnavailableAuthority&);
};
#endif

} // namespace kpb::measurement::durable_failed_view
