#include "privacy_measurement_child_output_authority.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <openssl/sha.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpb::measurement::runtime_bridge {
namespace {

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

void close_fd(int& fd) noexcept {
    if (fd < 0) return;
    while (::close(fd) != 0 && errno == EINTR) {}
    fd = -1;
}

WorkerBinding selected_worker(const PrivateChildOutputOffer& offer) {
    switch (offer.role) {
    case RuntimeChildRole::Observer: return offer.binding.observer_worker;
    case RuntimeChildRole::OwnerScore: return offer.binding.score_worker;
    case RuntimeChildRole::Aggregate:
    case RuntimeChildRole::OwnerComparison: refuse();
    }
    refuse();
}

void valid(const PrivateChildOutputOffer& offer) {
    validate_measurement_run_binding(offer.binding);
    const auto* abi = measurement_output_abi(offer.role);
    need(abi != nullptr &&
         offer.exact_size == abi->exact_bytes &&
         offer.output_abi_identity == abi->identity &&
         nonzero(offer.permit_identity) &&
         nonzero(offer.transport_session) &&
         nonzero(offer.output_authority_identity) &&
         nonzero(offer.output_abi_identity) &&
         offer.permit_identity != offer.transport_session &&
         offer.permit_identity != offer.output_authority_identity &&
         offer.transport_session != offer.output_authority_identity &&
         offer.worker == selected_worker(offer));
    const bool owner_role = offer.role == RuntimeChildRole::OwnerScore;
    need((owner_role && offer.owner < 3) ||
         (!owner_role && offer.owner == NO_OWNER));
}

std::vector<unsigned char> read_all(int fd, std::uint64_t size) {
    std::vector<unsigned char> bytes(static_cast<std::size_t>(size));
    std::uint64_t at = 0;
    while (at < size) {
        const auto target = static_cast<std::size_t>(
            std::min<std::uint64_t>(1U << 16, size - at));
        ssize_t count;
        do {
            count = ::pread(fd, bytes.data() + at, target,
                            static_cast<off_t>(at));
        } while (count < 0 && errno == EINTR);
        need(count > 0);
        at += static_cast<std::uint64_t>(count);
    }
    return bytes;
}

Digest hash_bytes(std::span<const unsigned char> bytes) {
    Digest result{};
    need(SHA256(bytes.data(), bytes.size(), result.data()) != nullptr &&
         nonzero(result));
    return result;
}

Digest retained_output_identity(
        const PrivateChildOutputCompletion& completion,
        const Digest& content_hash) {
    std::vector<unsigned char> bytes;
    static constexpr char domain[] =
        "KPB_SEALED_MEASUREMENT_CHILD_OUTPUT_V1\n";
    bytes.insert(bytes.end(), domain, domain + sizeof(domain) - 1);
    bytes.push_back(static_cast<unsigned char>(completion.offer.role));
    for (unsigned shift = 0; shift < 32; shift += 8)
        bytes.push_back(static_cast<unsigned char>(
            completion.offer.owner >> shift));
    for (const auto* value : {
             &completion.offer.permit_identity,
             &completion.offer.transport_session,
             &completion.offer.output_authority_identity,
             &completion.offer.output_abi_identity,
             &content_hash, &completion.process_identity,
             &completion.child_exit_identity})
        bytes.insert(bytes.end(), value->begin(), value->end());
    for (unsigned shift = 0; shift < 64; shift += 8)
        bytes.push_back(static_cast<unsigned char>(
            completion.offer.exact_size >> shift));
    return hash_bytes(bytes);
}

int reopen(int fd, int flags) {
    std::array<char, 64> path{};
    const int count = std::snprintf(
        path.data(), path.size(), "/proc/self/fd/%d", fd);
    need(count > 0 && static_cast<std::size_t>(count) < path.size());
    const int result = ::open(path.data(), flags | O_CLOEXEC);
    need(result >= 0);
    return result;
}

} // namespace

struct PendingChildOutputAuthority::Storage {
    PrivateChildOutputOffer offer;
    int parent_fd{-1};
    int child_fd{-1};
    std::uint64_t device{};
    std::uint64_t inode{};
    std::atomic_bool live{true};
    ~Storage() { close_fd(parent_fd); close_fd(child_fd); }
};

struct SealedChildOutputAuthority::Storage {
    PrivateChildOutputCompletion completion;
    int read_fd{-1};
    std::uint64_t device{};
    std::uint64_t inode{};
    Digest content_hash{};
    Digest retained_identity{};
    ~Storage() { close_fd(read_fd); }
};

PendingChildOutputAuthority::PendingChildOutputAuthority(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }

PendingChildOutputAuthority::PendingChildOutputAuthority(
        PendingChildOutputAuthority&& other) noexcept
    : storage_(std::move(other.storage_)) {}

PendingChildOutputAuthority::~PendingChildOutputAuthority() = default;

int PendingChildOutputAuthority::take_child_fd() {
    need(storage_ != nullptr && storage_->live.load() &&
         storage_->child_fd >= 0);
    return std::exchange(storage_->child_fd, -1);
}

AuthenticatedChildOutputCompletionAuthority::
AuthenticatedChildOutputCompletionAuthority(
        PrivateChildOutputCompletion completion)
    : completion_(std::move(completion)) {}

AuthenticatedChildOutputCompletionAuthority::
AuthenticatedChildOutputCompletionAuthority(
        AuthenticatedChildOutputCompletionAuthority&& other) noexcept
    : completion_(other.completion_), live_(other.live_.exchange(false)) {}

SealedChildOutputAuthority::SealedChildOutputAuthority(
        std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) { need(storage_ != nullptr); }

SealedChildOutputAuthority::SealedChildOutputAuthority(
        SealedChildOutputAuthority&& other) noexcept
    : storage_(std::move(other.storage_)) {}

SealedChildOutputAuthority::~SealedChildOutputAuthority() = default;

PendingChildOutputAuthority MeasurementChildOutputPlane::begin(
        PrivateChildOutputOffer offer) {
    valid(offer);
    int parent = ::memfd_create(
        "kpb-measurement-child-output",
        MFD_CLOEXEC | MFD_ALLOW_SEALING);
    need(parent >= 0);
    int child = -1;
    try {
        struct stat selected{};
        need(::fstat(parent, &selected) == 0 &&
             S_ISREG(selected.st_mode) && selected.st_size == 0 &&
             ::fcntl(parent, F_GET_SEALS) == 0);
        child = reopen(parent, O_WRONLY);
        need((::fcntl(child, F_GETFL) & O_ACCMODE) == O_WRONLY);
        auto storage = std::make_unique<PendingChildOutputAuthority::Storage>();
        storage->offer = std::move(offer);
        storage->parent_fd = std::exchange(parent, -1);
        storage->child_fd = std::exchange(child, -1);
        storage->device = static_cast<std::uint64_t>(selected.st_dev);
        storage->inode = static_cast<std::uint64_t>(selected.st_ino);
        return PendingChildOutputAuthority(std::move(storage));
    } catch (...) {
        close_fd(child);
        close_fd(parent);
        throw;
    }
}

SealedChildOutputAuthority MeasurementChildOutputPlane::finish(
        PendingChildOutputAuthority&& pending,
        AuthenticatedChildOutputCompletionAuthority&& completion) {
    const bool pending_present = pending.storage_ != nullptr;
    const bool pending_live = pending_present ?
        pending.storage_->live.exchange(false) : false;
    const bool completion_live = completion.live_.exchange(false);
    need(pending_present && pending_live && completion_live);
    auto& selected = *pending.storage_;
    const auto& observed = completion.completion_;
    int read_fd = -1;
    try {
        valid(selected.offer);
        need(selected.parent_fd >= 0 && selected.child_fd == -1 &&
             observed.offer == selected.offer &&
             nonzero(observed.content_hash) &&
             observed.content_hash !=
                 selected.offer.output_authority_identity &&
             nonzero(observed.process_identity) &&
             nonzero(observed.child_exit_identity) &&
             observed.process_identity != observed.child_exit_identity &&
             observed.authenticated_pid > 1 &&
             observed.waited_pid == observed.authenticated_pid &&
             observed.exit_code == 0 && observed.term_signal == 0 &&
             observed.credentials_verified && observed.eof_observed);
        struct stat before{};
        need(::fstat(selected.parent_fd, &before) == 0 &&
             S_ISREG(before.st_mode) &&
             static_cast<std::uint64_t>(before.st_dev) == selected.device &&
             static_cast<std::uint64_t>(before.st_ino) == selected.inode &&
             static_cast<std::uint64_t>(before.st_size) ==
                 selected.offer.exact_size &&
             ::fcntl(selected.parent_fd, F_GET_SEALS) == 0);
        const auto body = read_all(
            selected.parent_fd, selected.offer.exact_size);
        need(validate_measurement_output_abi(selected.offer.role, body));
        const Digest content = hash_bytes(body);
        need(content == observed.content_hash);
        constexpr int seals =
            F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
        need(::fcntl(selected.parent_fd, F_ADD_SEALS, seals) == 0 &&
             (::fcntl(selected.parent_fd, F_GET_SEALS) & seals) == seals);
        read_fd = reopen(selected.parent_fd, O_RDONLY);
        struct stat after{};
        const auto reopened_body = read_all(
            read_fd, selected.offer.exact_size);
        need((::fcntl(read_fd, F_GETFL) & O_ACCMODE) == O_RDONLY &&
             (::fcntl(read_fd, F_GET_SEALS) & seals) == seals &&
             ::fstat(read_fd, &after) == 0 &&
             static_cast<std::uint64_t>(after.st_dev) == selected.device &&
             static_cast<std::uint64_t>(after.st_ino) == selected.inode &&
             static_cast<std::uint64_t>(after.st_size) ==
                 selected.offer.exact_size &&
             validate_measurement_output_abi(
                 selected.offer.role, reopened_body) &&
             hash_bytes(reopened_body) == content);
        auto sealed = std::make_unique<SealedChildOutputAuthority::Storage>();
        sealed->completion = observed;
        sealed->read_fd = std::exchange(read_fd, -1);
        sealed->device = selected.device;
        sealed->inode = selected.inode;
        sealed->content_hash = content;
        sealed->retained_identity = retained_output_identity(observed, content);
        need(nonzero(sealed->retained_identity));
        close_fd(selected.parent_fd);
        return SealedChildOutputAuthority(std::move(sealed));
    } catch (...) {
        close_fd(read_fd);
        refuse();
    }
}

const PrivateChildOutputCompletion&
SealedChildOutputAuthority::retained_completion() const {
    need(storage_ != nullptr && storage_->read_fd >= 0);
    return storage_->completion;
}

const Digest& SealedChildOutputAuthority::retained_identity() const {
    need(storage_ != nullptr && storage_->read_fd >= 0 &&
         nonzero(storage_->retained_identity));
    return storage_->retained_identity;
}

int SealedChildOutputAuthority::native_phase_scope_read_fd() const {
    need(storage_ != nullptr && storage_->read_fd >= 0 &&
         storage_->completion.offer.role == RuntimeChildRole::Observer &&
         storage_->completion.offer.output_abi_identity ==
             OBSERVER_OUTPUT_ABI.identity &&
         storage_->completion.offer.exact_size ==
             OBSERVER_OUTPUT_ABI.exact_bytes);
    return storage_->read_fd;
}

int SealedChildOutputAuthority::owner_score_split_read_fd() const {
    need(storage_ != nullptr && storage_->read_fd >= 0 &&
         storage_->completion.offer.role == RuntimeChildRole::OwnerScore &&
         storage_->completion.offer.output_abi_identity ==
             OWNER_SCORE_OUTPUT_ABI.identity &&
         storage_->completion.offer.exact_size ==
             OWNER_SCORE_OUTPUT_ABI.exact_bytes);
    return storage_->read_fd;
}

#ifdef KPB_MEASUREMENT_CHILD_OUTPUT_TEST_SETUP
PendingChildOutputAuthority MeasurementChildOutputPlane::test_only_begin(
        PrivateChildOutputOffer offer) {
    return begin(std::move(offer));
}

int PendingChildOutputAuthority::test_only_take_child_fd() {
    return take_child_fd();
}

AuthenticatedChildOutputCompletionAuthority
AuthenticatedChildOutputCompletionAuthority::test_only_mint(
        PrivateChildOutputCompletion completion) {
    return AuthenticatedChildOutputCompletionAuthority(
        std::move(completion));
}

int SealedChildOutputAuthority::test_only_duplicate_read_fd() const {
    need(storage_ != nullptr && storage_->read_fd >= 0);
    const int result = ::fcntl(storage_->read_fd, F_DUPFD_CLOEXEC, 80);
    need(result >= 80);
    return result;
}

bool SealedChildOutputAuthority::test_only_matches(
        const PrivateChildOutputCompletion& completion,
        const Digest& content_hash) const {
    return storage_ != nullptr && storage_->read_fd >= 0 &&
           storage_->completion == completion &&
           storage_->content_hash == content_hash;
}
#endif

} // namespace kpb::measurement::runtime_bridge
