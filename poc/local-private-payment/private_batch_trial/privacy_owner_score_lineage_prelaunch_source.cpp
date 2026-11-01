#include "privacy_owner_score_lineage_source_authority.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <memory>
#include <openssl/evp.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace kpb::measurement::score_output_lineage_source {
namespace {

using Plan = kpi::mpc::financial::registered_driver::
    RegisteredSelectedProducerPrelaunchPlan;

[[noreturn]] void refuse() {
    throw std::runtime_error("selected-prelaunch-source-refused");
}
void need(bool value) { if (!value) refuse(); }
bool nonzero(const SourceDigest& value) {
    return std::any_of(value.begin(), value.end(),
        [](unsigned char byte) { return byte != 0; });
}
void close_once(int& fd) noexcept {
    const int selected = std::exchange(fd, -1);
    if (selected >= 0) (void)::close(selected);
}

struct ExactSourceFile final {
    std::uint64_t device{};
    std::uint64_t inode{};
    std::uint64_t size{};
    std::uint32_t mode{};
    SourceDigest sha256{};
    bool operator==(const ExactSourceFile&) const = default;
};

SourceDigest exact_sha256(int fd, std::uint64_t size) {
    struct ContextDeleter final {
        void operator()(EVP_MD_CTX* context) const noexcept {
            EVP_MD_CTX_free(context);
        }
    };
    std::unique_ptr<EVP_MD_CTX, ContextDeleter> context(EVP_MD_CTX_new());
    need(context != nullptr &&
         EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) == 1);
    std::array<unsigned char, 64 * 1024> buffer{};
    std::uint64_t offset{};
    while (offset < size) {
        const auto requested = static_cast<std::size_t>(
            std::min<std::uint64_t>(buffer.size(), size - offset));
        const auto count = ::pread(fd, buffer.data(), requested,
                                   static_cast<off_t>(offset));
        if (count < 0 && errno == EINTR) continue;
        need(count > 0 &&
             EVP_DigestUpdate(context.get(), buffer.data(),
                              static_cast<std::size_t>(count)) == 1);
        offset += static_cast<std::uint64_t>(count);
    }
    SourceDigest result{};
    unsigned result_bytes{};
    need(EVP_DigestFinal_ex(context.get(), result.data(), &result_bytes) == 1 &&
         result_bytes == result.size() && nonzero(result));
    return result;
}

ExactSourceFile exact_source_file(int fd, bool executable) {
    const int status = ::fcntl(fd, F_GETFL);
    const int descriptor = ::fcntl(fd, F_GETFD);
    const int seals = ::fcntl(fd, F_GET_SEALS);
    struct stat before{};
    need(fd >= 0 && status >= 0 && (status & O_ACCMODE) == O_RDONLY &&
         descriptor >= 0 && (descriptor & FD_CLOEXEC) != 0 && seals >= 0 &&
         (seals & (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK |
                   F_SEAL_SEAL)) ==
             (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) &&
         ::fstat(fd, &before) == 0 && S_ISREG(before.st_mode) &&
         before.st_uid == ::getuid() && before.st_nlink == 0 &&
         before.st_size > 0 &&
         (before.st_mode & 0777) == (executable ? 0500 : 0400));
    const auto sha = exact_sha256(
        fd, static_cast<std::uint64_t>(before.st_size));
    struct stat after{};
    need(::fstat(fd, &after) == 0 && before.st_dev == after.st_dev &&
         before.st_ino == after.st_ino && before.st_size == after.st_size &&
         before.st_mode == after.st_mode && before.st_nlink == after.st_nlink &&
         before.st_uid == after.st_uid && before.st_gid == after.st_gid &&
         before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
         before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
         before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
         before.st_ctim.tv_nsec == after.st_ctim.tv_nsec);
    return {
        .device = static_cast<std::uint64_t>(before.st_dev),
        .inode = static_cast<std::uint64_t>(before.st_ino),
        .size = static_cast<std::uint64_t>(before.st_size),
        .mode = static_cast<std::uint32_t>(before.st_mode),
        .sha256 = sha,
    };
}

} // namespace

struct SelectedOwnerScoreLineagePrelaunchSourceAuthority::Storage final {
    Plan plan;
    int selection_fd{-1};
    int worker_fd{-1};
    ExactSourceFile selection;
    ExactSourceFile worker;
    bool live{true};
    ~Storage() {
        close_once(selection_fd);
        close_once(worker_fd);
    }
};

SelectedOwnerScoreLineagePrelaunchSourceAuthority::ActivationBundle::
ActivationBundle(Plan selected_plan, int selected_selection_fd,
                 int selected_worker_fd,
                 SourceDigest selected_worker_sha256) noexcept
    : plan(std::move(selected_plan)), selection_fd(selected_selection_fd),
      worker_fd(selected_worker_fd), worker_sha256(selected_worker_sha256) {}
SelectedOwnerScoreLineagePrelaunchSourceAuthority::ActivationBundle::
ActivationBundle(ActivationBundle&& other) noexcept
    : plan(std::move(other.plan)),
      selection_fd(std::exchange(other.selection_fd, -1)),
      worker_fd(std::exchange(other.worker_fd, -1)),
      worker_sha256(std::exchange(other.worker_sha256, {})) {}
SelectedOwnerScoreLineagePrelaunchSourceAuthority::ActivationBundle::
~ActivationBundle() {
    close_once(selection_fd);
    close_once(worker_fd);
}

SelectedOwnerScoreLineagePrelaunchSourceAuthority::
SelectedOwnerScoreLineagePrelaunchSourceAuthority(
        std::unique_ptr<Storage> storage) noexcept
    : storage_(std::move(storage)) {}
SelectedOwnerScoreLineagePrelaunchSourceAuthority::
SelectedOwnerScoreLineagePrelaunchSourceAuthority(
        SelectedOwnerScoreLineagePrelaunchSourceAuthority&&) noexcept =
    default;
SelectedOwnerScoreLineagePrelaunchSourceAuthority::
~SelectedOwnerScoreLineagePrelaunchSourceAuthority() = default;

SelectedOwnerScoreLineagePrelaunchSourceAuthority::ActivationBundle
SelectedOwnerScoreLineagePrelaunchSourceAuthority::
consume_for_selected_activation() && {
    need(storage_ != nullptr && storage_->live);
    auto storage = std::move(storage_);
    storage->live = false;
    const auto selection = exact_source_file(storage->selection_fd, false);
    const auto worker = exact_source_file(storage->worker_fd, true);
    need(selection == storage->selection && worker == storage->worker &&
         selection.sha256 == storage->plan.comparison_selection &&
         selection.device != 0 && selection.inode != 0 &&
         worker.device != 0 && worker.inode != 0 &&
         (selection.device != worker.device ||
          selection.inode != worker.inode));
    return ActivationBundle(
        std::move(storage->plan),
        std::exchange(storage->selection_fd, -1),
        std::exchange(storage->worker_fd, -1), worker.sha256);
}

#ifdef KPB_SELECTED_PRODUCER_ACTIVATION_TEST_SETUP
SelectedOwnerScoreLineagePrelaunchSourceAuthority
SelectedOwnerScoreLineagePrelaunchSourceTestBridge::mint(
        Plan plan, int selection_fd, int worker_fd) {
    auto storage = std::make_unique<
        SelectedOwnerScoreLineagePrelaunchSourceAuthority::Storage>();
    storage->selection_fd = selection_fd;
    storage->worker_fd = worker_fd;
    try {
        storage->selection = exact_source_file(selection_fd, false);
        storage->worker = exact_source_file(worker_fd, true);
        need(storage->selection.sha256 == plan.comparison_selection &&
             storage->selection.device != 0 &&
             storage->selection.inode != 0 &&
             storage->worker.device != 0 && storage->worker.inode != 0 &&
             (storage->selection.device != storage->worker.device ||
              storage->selection.inode != storage->worker.inode));
        storage->plan = std::move(plan);
        return SelectedOwnerScoreLineagePrelaunchSourceAuthority(
            std::move(storage));
    } catch (...) { refuse(); }
}
#endif

} // namespace kpb::measurement::score_output_lineage_source
