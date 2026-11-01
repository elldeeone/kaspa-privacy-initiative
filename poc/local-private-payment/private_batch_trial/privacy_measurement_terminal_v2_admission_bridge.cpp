#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "privacy_measurement_observer_capture_bridge.hpp"

#include "native_terminal_completion.hpp"
#include "privacy_measurement_authority.hpp"
#include "privacy_measurement_observer_admission_storage.hpp"
#include "privacy_measurement_structural_continuity_section_schema.hpp"

#include <algorithm>
#include <fcntl.h>
#include <array>
#include <cerrno>
#include <cstdio>
#include <memory>
#include <openssl/evp.h>
#include <span>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <utility>

namespace kpb::measurement::runtime_bridge {
namespace {

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

void close_fd(int& fd) noexcept {
    if (fd < 0) return;
    while (::close(fd) != 0 && errno == EINTR) {}
    fd = -1;
}

class Fd final {
    int value_{-1};
public:
    explicit Fd(int value = -1) : value_(value) {}
    ~Fd() { close_fd(value_); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    int get() const { return value_; }
    int release() { return std::exchange(value_, -1); }
};

void write_all(int fd, std::span<const unsigned char> bytes) {
    std::size_t at = 0;
    while (at < bytes.size()) {
        const auto count = ::write(
            fd, bytes.data() + at, bytes.size() - at);
        if (count < 0 && errno == EINTR) continue;
        need(count > 0);
        at += static_cast<std::size_t>(count);
    }
}

void write_u32(int fd, std::uint32_t value) {
    std::array<unsigned char, 4> bytes{};
    for (unsigned index = 0; index < bytes.size(); ++index)
        bytes[index] = static_cast<unsigned char>(value >> (8 * index));
    write_all(fd, bytes);
}

void write_u64(int fd, std::uint64_t value) {
    std::array<unsigned char, 8> bytes{};
    for (unsigned index = 0; index < bytes.size(); ++index)
        bytes[index] = static_cast<unsigned char>(value >> (8 * index));
    write_all(fd, bytes);
}

void write_digest(int fd, const Digest& value) { write_all(fd, value); }

int seal_and_reopen_read_only(int writable, std::uint64_t exact_size) {
    constexpr int required_seals =
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    struct stat before{};
    need(::fstat(writable, &before) == 0 && S_ISREG(before.st_mode) &&
         static_cast<std::uint64_t>(before.st_size) == exact_size &&
         ::fchmod(writable, 0400) == 0 &&
         ::fcntl(writable, F_ADD_SEALS, required_seals) == 0 &&
         (::fcntl(writable, F_GET_SEALS) & required_seals) ==
             required_seals);
    std::array<char, 64> path{};
    const int count = std::snprintf(
        path.data(), path.size(), "/proc/self/fd/%d", writable);
    need(count > 0 && static_cast<std::size_t>(count) < path.size());
    const int result = ::open(path.data(), O_RDONLY | O_CLOEXEC);
    struct stat after{};
    need(result >= 0 && ::fstat(result, &after) == 0 &&
         before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
         before.st_size == after.st_size &&
         (::fcntl(result, F_GETFL) & O_ACCMODE) == O_RDONLY &&
         (::fcntl(result, F_GETFD) & FD_CLOEXEC) != 0 &&
         (::fcntl(result, F_GET_SEALS) & required_seals) ==
             required_seals);
    return result;
}

void destroy_terminal_v2_model_admission(
        native_terminal::TerminalV2ModelAdmissionAuthority* value) noexcept {
    delete value;
}

bool exact_archive_slot(
        int fd, std::uint64_t device, std::uint64_t inode,
        std::uint64_t size, const Digest& expected_hash) {
    struct stat before{};
    if (fd < 0 || ::fstat(fd, &before) != 0 ||
        !S_ISREG(before.st_mode) || before.st_nlink != 0 ||
        (before.st_mode & 0777) != 0600 ||
        static_cast<std::uint64_t>(before.st_dev) != device ||
        static_cast<std::uint64_t>(before.st_ino) != inode ||
        static_cast<std::uint64_t>(before.st_size) != size ||
        (::fcntl(fd, F_GETFL) & O_ACCMODE) != O_RDONLY ||
        (::fcntl(fd, F_GETFD) & FD_CLOEXEC) == 0)
        return false;
    struct ContextDeleter {
        void operator()(EVP_MD_CTX* value) const { EVP_MD_CTX_free(value); }
    };
    std::unique_ptr<EVP_MD_CTX, ContextDeleter> context(EVP_MD_CTX_new());
    if (context == nullptr ||
        EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1)
        return false;
    std::array<unsigned char, 65536> bytes{};
    std::uint64_t at = 0;
    while (at < size) {
        const auto wanted = static_cast<std::size_t>(
            std::min<std::uint64_t>(bytes.size(), size - at));
        ssize_t count;
        do {
            count = ::pread(fd, bytes.data(), wanted,
                            static_cast<off_t>(at));
        } while (count < 0 && errno == EINTR);
        if (count <= 0 ||
            EVP_DigestUpdate(context.get(), bytes.data(),
                             static_cast<std::size_t>(count)) != 1)
            return false;
        at += static_cast<std::uint64_t>(count);
    }
    Digest observed{};
    unsigned length = 0;
    struct stat after{};
    return EVP_DigestFinal_ex(context.get(), observed.data(), &length) == 1 &&
           length == observed.size() && observed == expected_hash &&
           ::fstat(fd, &after) == 0 && before.st_dev == after.st_dev &&
           before.st_ino == after.st_ino &&
           before.st_size == after.st_size && before.st_mode == after.st_mode &&
           before.st_nlink == after.st_nlink;
}

} // namespace

ObserverTerminalCaptureJoin::ObserverTerminalCaptureJoin(
        ObserverAdmissionAuthority&& admission)
    : admission_(std::in_place, std::move(admission)) {}

ObserverTerminalCaptureJoin::ObserverTerminalCaptureJoin(
        ObserverTerminalCaptureJoin&& other) noexcept
    : admission_(std::move(other.admission_)),
      live_(other.live_.exchange(false)) {}

ObserverTerminalCaptureJoin
ObserverCaptureCapsuleBridge::attach_terminal_v2(
        ObserverAdmissionAuthority&& supplied_admission,
        native_terminal::TerminalV2ModelAdmissionAuthority&&
            supplied_terminal) {
    auto admission = std::optional<ObserverAdmissionAuthority>(
        std::in_place, std::move(supplied_admission));
    auto terminal =
        std::make_unique<native_terminal::TerminalV2ModelAdmissionAuthority>(
            std::move(supplied_terminal));
    try {
        need(admission->storage_ != nullptr &&
             terminal->live_.exchange(false) &&
             terminal->structural_continuity_ != nullptr &&
             terminal->structural_continuity_->live_.exchange(false));
        terminal->validate_consumed_for_observer_join();

        auto& storage = *admission->storage_;
        const auto& evidence = terminal->evidence_;
        const auto& continuity =
            terminal->structural_continuity_->evidence_;
        const auto& producer = terminal->producer_->public_receipt();
        need(storage.terminal_v2_model_admission == nullptr &&
             storage.destroy_terminal_v2_model_admission == nullptr &&
             storage.structural_continuity_fd < 0 &&
             storage.structural_continuity_size == 0 &&
             storage.structural_continuity_identity == Digest{} &&
             storage.binding == evidence.binding &&
             continuity.binding == evidence.binding &&
             continuity.classification == evidence.classification &&
             continuity.structural_projection_continuity &&
             !continuity.accepted_chain_continuity &&
             producer.binding == storage.binding &&
             producer.binding.classification == evidence.classification &&
             producer.opaque_closure_authority_identity ==
                 evidence.producer_closure_authority_identity &&
             !storage.matched_producer_closure.has_value());

        if (storage.test_only) {
#ifndef KPB_MEASUREMENT_AUTHORITY_TEST_SETUP
            refuse();
#endif
        } else {
            need(storage.sealed_archive && storage.directory_fd < 0 &&
                 storage.opaque_closure_authority_identity ==
                     producer.opaque_closure_authority_identity &&
                 storage.producer_process_identity ==
                     producer.producer_process_identity &&
                 storage.c03_producer_child_exit != Digest{} &&
                 storage.c03_producer_receipt != Digest{});
            for (unsigned slot = 0; slot < storage.archive_fds.size();
                 ++slot)
                need(exact_archive_slot(
                    storage.archive_fds[slot],
                    storage.archive_devices[slot],
                    storage.archive_inodes[slot],
                    storage.archive_sizes[slot],
                    storage.archive_stream_evidence[slot].record_root));
            constexpr std::array<unsigned, 2> terminal_slots{1, 6};
            for (unsigned index = 0; index < terminal_slots.size();
                 ++index) {
                const auto& archived = storage.archive_stream_evidence[
                    terminal_slots[index]];
                const auto& round = evidence.rounds[index];
                need(archived.record_root == round.record_root &&
                     archived.end_frame_identity ==
                         round.end_frame_identity &&
                     archived.eof_identity == round.expected_eof_identity &&
                     archived.record_count == round.record_count &&
                     archived.payload_bytes == round.payload_bytes &&
                     archived.raw_wire_bytes == round.raw_wire_bytes);
            }
        }

        namespace structural = structural_continuity_section_schema;
        Fd writable(::memfd_create(
            "kpb-structural-projection-continuity",
            MFD_CLOEXEC | MFD_ALLOW_SEALING));
        need(writable.get() >= 0);
        write_all(writable.get(), structural::MAGIC);
        write_u32(writable.get(), structural::VERSION);
        write_u32(writable.get(), static_cast<std::uint32_t>(
            structural::SECTION_BYTES));
        const std::array<unsigned char, 4> tags{
            static_cast<unsigned char>(continuity.classification),
            1, 0, static_cast<unsigned char>(structural::ROUND_COUNT)};
        write_all(writable.get(), tags);
        write_digest(writable.get(), continuity.continuity_identity);
        for (const auto& round : continuity.rounds) {
            for (const auto* value : {
                     &round.projection, &round.accepted_input_head,
                     &round.successor_head, &round.retained_projection,
                     &round.fork_binding, &round.intake,
                     &round.mapping_source, &round.stream_process,
                     &round.stream_child_exit, &round.child_process,
                     &round.child_exit, &round.producer_stream_process,
                     &round.producer_stream_child_exit,
                     &round.private_completion})
                write_digest(writable.get(), *value);
            const auto& structural = round.structural;
            for (const auto* value : {
                     &structural.projection_identity,
                     &structural.profile_context_identity,
                     &structural.old_context_identity,
                     &structural.old_reserve_outpoint_identity,
                     &structural.old_cm_root, &structural.old_nf_root,
                     &structural.new_cm_root, &structural.new_nf_root,
                     &structural.old_state_identity,
                     &structural.successor_state_identity,
                     &structural.old_script_identity,
                     &structural.successor_script_identity,
                     &structural.structural_old_context_identity,
                     &structural.structural_successor_context_identity,
                     &structural.structural_projection_identity})
                write_digest(writable.get(), *value);
            write_u32(writable.get(), structural.old_cm_count);
            write_u32(writable.get(), structural.old_nf_count);
            write_u32(writable.get(), structural.new_cm_count);
            write_u32(writable.get(), structural.new_nf_count);
            write_u64(writable.get(), structural.old_reserve_sompi);
            write_u64(writable.get(), structural.new_reserve_sompi);
            write_u64(writable.get(), structural.fee_sompi);
        }
        Fd readonly(seal_and_reopen_read_only(
            writable.get(), structural::SECTION_BYTES));
        storage.structural_continuity_fd = readonly.release();
        storage.structural_continuity_size = structural::SECTION_BYTES;
        storage.structural_continuity_identity =
            continuity.continuity_identity;

        storage.destroy_terminal_v2_model_admission =
            &destroy_terminal_v2_model_admission;
        storage.terminal_v2_model_admission = terminal.release();
        return ObserverTerminalCaptureJoin(std::move(*admission));
    } catch (...) {
        refuse();
    }
}

} // namespace kpb::measurement::runtime_bridge

namespace kpb::measurement {
namespace {

[[noreturn]] void refuse_trial_join() { throw Refused(); }
void need_trial_join(bool value) { if (!value) refuse_trial_join(); }

} // namespace

void runtime_bridge::ObserverCaptureCapsuleBridge::submit_terminal_capture(
        TrialCaptureJoiner& joiner,
        runtime_bridge::ObserverTerminalCaptureJoin&& joined) {
    try {
        need_trial_join(joined.live_.exchange(false) &&
                        joined.admission_.has_value());
        auto admission = std::move(*joined.admission_);
        joined.admission_.reset();
        need_trial_join(admission.storage_ != nullptr &&
             admission.storage_->terminal_v2_model_admission != nullptr &&
             admission.storage_->destroy_terminal_v2_model_admission !=
                 nullptr);
        auto& terminal =
            *admission.storage_->terminal_v2_model_admission;
        joiner.submit_terminal_authority(std::move(admission), terminal);
    } catch (...) {
        std::lock_guard guard(joiner.mutex_);
        joiner.poisoned_ = true;
        refuse_trial_join();
    }
}

void TrialCaptureJoiner::submit_terminal_authority(
        runtime_bridge::ObserverAdmissionAuthority&& admission,
        native_terminal::TerminalV2ModelAdmissionAuthority& terminal) {
    std::lock_guard guard(mutex_);
    need_trial_join(!poisoned_ && !finished_ && !producer_.has_value() &&
                    !observer_admission_.has_value());
    terminal.validate_consumed_for_observer_join();
    need_trial_join(terminal.evidence_.binding == binding_ &&
                    terminal.producer_.has_value());

    auto& producer = *terminal.producer_;
    need_trial_join(producer.live_.exchange(false));
    producer.validate_for_native_terminal_join();
    need_trial_join(producer.receipt_.binding == binding_ &&
                    producer.receipt_.opaque_closure_authority_identity ==
                        terminal.evidence_.
                            producer_closure_authority_identity);
    admission.require_matches(
        binding_, producer.receipt_, producer.evidence_);
    producer_ = producer.receipt_;
    producer_evidence_ = producer.evidence_;
    observer_admission_.emplace(std::move(admission));
}

void TrialCaptureJoiner::submit(
        runtime_bridge::ObserverTerminalCaptureJoin&& joined) {
    runtime_bridge::ObserverCaptureCapsuleBridge::submit_terminal_capture(
        *this, std::move(joined));
}

} // namespace kpb::measurement
