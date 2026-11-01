#include "privacy_measurement_parent_manifest.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <memory>
#include <openssl/evp.h>
#include <span>
#include <string_view>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpb::measurement {
namespace {

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

constexpr int REQUIRED_SEALS =
    F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
        [](unsigned char byte) { return byte != 0; });
}

void close_fd(int& fd) noexcept {
    if (fd < 0) return;
    while (::close(fd) != 0 && errno == EINTR) {}
    fd = -1;
}

struct Fingerprint {
    std::uint64_t device{};
    std::uint64_t inode{};
    std::uint64_t size{};
    std::uint32_t mode{};
    std::uint64_t modified_seconds{};
    std::uint64_t modified_nanoseconds{};
    std::uint64_t changed_seconds{};
    std::uint64_t changed_nanoseconds{};
    bool operator==(const Fingerprint&) const = default;
};

Fingerprint fingerprint(int fd, bool require_sealed) {
    struct stat status{};
    const int flags = ::fcntl(fd, F_GETFL);
    const int descriptor_flags = ::fcntl(fd, F_GETFD);
    need(flags >= 0 && descriptor_flags >= 0 &&
         (flags & O_ACCMODE) == O_RDONLY &&
         (descriptor_flags & FD_CLOEXEC) != 0 &&
         ::fstat(fd, &status) == 0 && S_ISREG(status.st_mode) &&
         status.st_size > 0);
    if (require_sealed)
        need((::fcntl(fd, F_GET_SEALS) & REQUIRED_SEALS) ==
             REQUIRED_SEALS);
    return {
        .device = static_cast<std::uint64_t>(status.st_dev),
        .inode = static_cast<std::uint64_t>(status.st_ino),
        .size = static_cast<std::uint64_t>(status.st_size),
        .mode = static_cast<std::uint32_t>(status.st_mode),
        .modified_seconds =
            static_cast<std::uint64_t>(status.st_mtim.tv_sec),
        .modified_nanoseconds =
            static_cast<std::uint64_t>(status.st_mtim.tv_nsec),
        .changed_seconds =
            static_cast<std::uint64_t>(status.st_ctim.tv_sec),
        .changed_nanoseconds =
            static_cast<std::uint64_t>(status.st_ctim.tv_nsec),
    };
}

int duplicate_high(int fd) {
    int result;
    do { result = ::fcntl(fd, F_DUPFD_CLOEXEC, 64); }
    while (result < 0 && errno == EINTR);
    need(result >= 0);
    return result;
}

Digest hash_fd(int fd, std::uint64_t size) {
    struct Deleter {
        void operator()(EVP_MD_CTX* value) const {
            EVP_MD_CTX_free(value);
        }
    };
    std::unique_ptr<EVP_MD_CTX, Deleter> context(EVP_MD_CTX_new());
    need(context != nullptr &&
         EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) == 1);
    std::array<unsigned char, 1U << 16> buffer{};
    std::uint64_t at = 0;
    while (at < size) {
        const auto wanted = static_cast<std::size_t>(
            std::min<std::uint64_t>(buffer.size(), size - at));
        ssize_t count;
        do {
            count = ::pread(fd, buffer.data(), wanted,
                            static_cast<off_t>(at));
        } while (count < 0 && errno == EINTR);
        need(count > 0 && static_cast<std::size_t>(count) <= wanted &&
             EVP_DigestUpdate(context.get(), buffer.data(),
                              static_cast<std::size_t>(count)) == 1);
        at += static_cast<std::uint64_t>(count);
    }
    unsigned char extra{};
    ssize_t trailing;
    do {
        trailing = ::pread(fd, &extra, 1, static_cast<off_t>(size));
    } while (trailing < 0 && errno == EINTR);
    need(trailing == 0);
    Digest result{};
    unsigned output_size = 0;
    need(EVP_DigestFinal_ex(context.get(), result.data(), &output_size) == 1 &&
         output_size == result.size() && nonzero(result));
    return result;
}

void add(std::vector<unsigned char>& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}

void add(std::vector<unsigned char>& out, const Digest& value) {
    out.insert(out.end(), value.begin(), value.end());
}

void add(std::vector<unsigned char>& out, std::uint64_t value) {
    for (unsigned index = 0; index < 8; ++index)
        out.push_back(static_cast<unsigned char>(value >> (8 * index)));
}

Digest hash(std::span<const unsigned char> bytes) {
    Digest result{};
    need(EVP_Digest(bytes.data(), bytes.size(), result.data(), nullptr,
                    EVP_sha256(), nullptr) == 1 && nonzero(result));
    return result;
}

struct SecretDigest final {
    Digest value{};
    SecretDigest() = default;
    SecretDigest(const SecretDigest&) = delete;
    SecretDigest& operator=(const SecretDigest&) = delete;
    SecretDigest(SecretDigest&& other) noexcept : value(other.value) {
        volatile unsigned char* bytes = other.value.data();
        for (std::size_t index = 0; index < other.value.size(); ++index)
            bytes[index] = 0;
    }
    ~SecretDigest() {
        volatile unsigned char* bytes = value.data();
        for (std::size_t index = 0; index < value.size(); ++index)
            bytes[index] = 0;
    }
};

#ifdef KPB_MEASUREMENT_PARENT_MANIFEST_TEST_SETUP
std::atomic_uint entropy_fault{0};
#endif

SecretDigest random_secret() {
    SecretDigest result;
#ifdef KPB_MEASUREMENT_PARENT_MANIFEST_TEST_SETUP
    if (entropy_fault.load() == 1) refuse();
    if (entropy_fault.load() == 2) {
        result.value.fill(0xa5);
        refuse();
    }
#endif
    ssize_t count;
    do {
        count = ::getrandom(result.value.data(), result.value.size(), 0);
    } while (count < 0 && errno == EINTR);
    need(count == static_cast<ssize_t>(result.value.size()) &&
         nonzero(result.value));
    return result;
}

} // namespace

struct ParentManifestArtifactSelectionAuthority::Storage {
    std::array<std::array<int, PARENT_MANIFEST_ARTIFACT_FIELDS>, 10> fds{};
    std::array<std::array<Fingerprint,
                          PARENT_MANIFEST_ARTIFACT_FIELDS>, 10>
        fingerprints{};
    bool selected_child_verified{};
    unsigned executable_component{};
    Digest selected_child_executable_identity{};
    Digest selected_child_launch_session{};
    Digest selected_child_exit_identity{};
    std::int64_t selected_child_pid{-1};
    Storage() {
        for (auto& component : fds) component.fill(-1);
    }
    ~Storage() {
        for (auto& component : fds)
            for (auto& fd : component) close_fd(fd);
    }
};

ParentManifestArtifactSelectionAuthority::
ParentManifestArtifactSelectionAuthority(std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) {
    need(storage_ != nullptr);
}

ParentManifestArtifactSelectionAuthority::
ParentManifestArtifactSelectionAuthority(
        ParentManifestArtifactSelectionAuthority&& other) noexcept
    : storage_(std::move(other.storage_)),
      live_(other.live_.exchange(false)) {}

ParentManifestArtifactSelectionAuthority::~
ParentManifestArtifactSelectionAuthority() = default;

void ParentManifestArtifactSelectionAuthority::bind_verified_selected_child(
        unsigned executable_component, Digest executable_identity,
        Digest launch_session, Digest child_exit_identity,
        std::int64_t child_pid) {
    need(live_.load() && storage_ != nullptr &&
         !storage_->selected_child_verified && executable_component < 10 &&
         nonzero(executable_identity) && nonzero(launch_session) &&
         nonzero(child_exit_identity) && child_pid > 1);
    storage_->selected_child_verified = true;
    storage_->executable_component = executable_component;
    storage_->selected_child_executable_identity = executable_identity;
    storage_->selected_child_launch_session = launch_session;
    storage_->selected_child_exit_identity = child_exit_identity;
    storage_->selected_child_pid = child_pid;
}

ParentManifestArtifactSelectionAuthority
ParentManifestArtifactSelector::source_owned_select(
        std::array<ParentManifestComponentArtifacts, 10>&& supplied) {
    std::array<std::array<int, PARENT_MANIFEST_ARTIFACT_FIELDS>, 10>
        claimed{};
    for (auto& component : claimed) component.fill(-1);
    try {
        for (unsigned component = 0; component < supplied.size();
             ++component)
            for (unsigned field = 0;
                 field < supplied[component].fds.size(); ++field)
                claimed[component][field] =
                    std::exchange(supplied[component].fds[field], -1);
        auto storage = std::make_unique<
            ParentManifestArtifactSelectionAuthority::Storage>();
        std::vector<std::pair<std::uint64_t, std::uint64_t>> seen;
        seen.reserve(10 * PARENT_MANIFEST_ARTIFACT_FIELDS);
        for (unsigned component = 0; component < supplied.size();
             ++component) {
            for (unsigned field = 0;
                 field < supplied[component].fds.size(); ++field) {
                const int source = claimed[component][field];
                const auto original = fingerprint(source, true);
                need(std::find(seen.begin(), seen.end(),
                               std::pair{original.device, original.inode}) ==
                     seen.end());
                seen.emplace_back(original.device, original.inode);
                int duplicate = duplicate_high(source);
                try {
                    need(fingerprint(duplicate, true) == original);
                    storage->fds[component][field] = duplicate;
                    duplicate = -1;
                    storage->fingerprints[component][field] = original;
                } catch (...) {
                    close_fd(duplicate);
                    throw;
                }
            }
        }
        for (auto& component : claimed)
            for (auto& fd : component) close_fd(fd);
        return ParentManifestArtifactSelectionAuthority(
            std::move(storage));
    } catch (...) {
        for (auto& component : claimed)
            for (auto& fd : component) close_fd(fd);
        refuse();
    }
}

#ifdef KPB_MEASUREMENT_PARENT_MANIFEST_TEST_SETUP
ParentManifestArtifactSelectionAuthority
ParentManifestArtifactSelector::select(
        std::array<ParentManifestComponentArtifacts, 10>&& supplied) {
    return source_owned_select(std::move(supplied));
}
#endif

ParentManifestRecomputationAuthority
ParentManifestRecomputationFactory::recompute(
        ParentManifestArtifactSelectionAuthority&& selection) {
    try {
        need(selection.live_.exchange(false) && selection.storage_ != nullptr);
        auto nonce = random_secret();
        std::array<ManifestEntry, 10> entries{};
        for (unsigned component = 0; component < entries.size();
             ++component) {
            std::array<Digest, PARENT_MANIFEST_ARTIFACT_FIELDS> identities{};
            for (unsigned field = 0; field < identities.size(); ++field) {
                const int fd = selection.storage_->fds[component][field];
                const auto before = fingerprint(fd, true);
                need(before ==
                     selection.storage_->fingerprints[component][field]);
                identities[field] = hash_fd(fd, before.size);
                need(fingerprint(fd, true) == before);
            }
            entries[component] = {
                .component = static_cast<ManifestComponent>(component + 1),
                .source_identity = identities[0],
                .build_identity = identities[1],
                .runtime_identity = identities[2],
                .assets_identity = identities[3],
                .pinned_executable_identity = identities[4],
                .launcher_identity = identities[5],
            };
        }
        const auto manifest_identity =
            recompute_finite_manifest_identity(entries);

        Digest parent_executable_identity{};
        if (selection.storage_->selected_child_verified) {
            need(selection.storage_->executable_component < entries.size());
            parent_executable_identity = entries[
                selection.storage_->executable_component]
                    .pinned_executable_identity;
            need(parent_executable_identity ==
                 selection.storage_->selected_child_executable_identity);
        } else {
#ifdef KPB_MEASUREMENT_PARENT_MANIFEST_TEST_SETUP
            int parent_executable = ::open(
                "/proc/self/exe", O_RDONLY | O_CLOEXEC);
            need(parent_executable >= 0);
            try {
                const auto before = fingerprint(parent_executable, false);
                parent_executable_identity = hash_fd(
                    parent_executable, before.size);
                need(fingerprint(parent_executable, false) == before);
                close_fd(parent_executable);
            } catch (...) {
                close_fd(parent_executable);
                throw;
            }
#else
            refuse();
#endif
        }

        need(::getpid() > 1 && ::getppid() >= 1);
        std::vector<unsigned char> process_bytes;
        add(process_bytes, "KPB_MEASUREMENT_PARENT_PROCESS_V1\n");
        add(process_bytes, nonce.value);
        add(process_bytes, manifest_identity);
        add(process_bytes, parent_executable_identity);
        add(process_bytes, static_cast<std::uint64_t>(::getpid()));
        add(process_bytes, static_cast<std::uint64_t>(::getppid()));
        if (selection.storage_->selected_child_verified) {
            add(process_bytes,
                selection.storage_->selected_child_launch_session);
            add(process_bytes,
                selection.storage_->selected_child_exit_identity);
            add(process_bytes, static_cast<std::uint64_t>(
                selection.storage_->selected_child_pid));
        }
        const auto parent_process_identity = hash(process_bytes);

        std::vector<unsigned char> recomputation_bytes;
        add(recomputation_bytes,
            "KPB_MEASUREMENT_PARENT_MANIFEST_RECOMPUTATION_V1\n");
        add(recomputation_bytes, nonce.value);
        add(recomputation_bytes, manifest_identity);
        add(recomputation_bytes, parent_process_identity);
        add(recomputation_bytes, parent_executable_identity);
        if (selection.storage_->selected_child_verified) {
            add(recomputation_bytes,
                selection.storage_->selected_child_launch_session);
            add(recomputation_bytes,
                selection.storage_->selected_child_exit_identity);
        }
        const auto recomputation_identity = hash(recomputation_bytes);
        need(recomputation_identity != manifest_identity &&
             recomputation_identity != parent_process_identity &&
             recomputation_identity != parent_executable_identity);

        PublicParentManifestRecomputation receipt{
            .manifest = {
                .manifest_identity = manifest_identity,
                .parent_recomputation_identity = recomputation_identity,
                .entries = entries,
            },
            .parent_process_identity = parent_process_identity,
            .parent_executable_identity = parent_executable_identity,
            .recomputation_receipt = recomputation_identity,
        };
        selection.storage_.reset();
        return ParentManifestRecomputationAuthority(std::move(receipt));
    } catch (...) {
        selection.storage_.reset();
        refuse();
    }
}

#ifdef KPB_MEASUREMENT_PARENT_MANIFEST_TEST_SETUP
void ParentManifestRecomputationFactory::test_only_force_entropy_failure(
        bool value) {
    entropy_fault.store(value ? 1U : 0U);
}

void ParentManifestRecomputationFactory::test_only_force_entropy_short_read(
        bool value) {
    entropy_fault.store(value ? 2U : 0U);
}
#endif

} // namespace kpb::measurement
