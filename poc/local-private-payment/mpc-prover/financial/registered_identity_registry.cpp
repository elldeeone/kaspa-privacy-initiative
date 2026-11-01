#include "registered_identity_registry.hpp"

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <limits>
#include <mutex>
#include <openssl/evp.h>
#include <set>
#include <string_view>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace kpi::mpc::financial::identity_registry {
namespace {
using Bytes = std::vector<unsigned char>;

constexpr std::size_t DIGEST_BYTES = 32;
constexpr std::size_t SELECTION_FIELDS = 8;
constexpr std::size_t EVENT_PREFIX_BYTES = 8 + 8 + SELECTION_FIELDS * DIGEST_BYTES + DIGEST_BYTES;
constexpr std::size_t EVENT_BYTES = EVENT_PREFIX_BYTES + DIGEST_BYTES;
constexpr std::size_t ANCHOR_HEADER_BYTES = 8 + DIGEST_BYTES + DIGEST_BYTES;
constexpr std::size_t ANCHOR_ROW_BYTES = 8 + DIGEST_BYTES;

struct StorageBinding {
    std::uint64_t journal_directory_device;
    std::uint64_t journal_directory_inode;
    std::uint64_t anchor_directory_device;
    std::uint64_t anchor_directory_inode;
    std::uint64_t journal_device;
    std::uint64_t journal_inode;
    std::uint64_t anchor_device;
    std::uint64_t anchor_inode;
};

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add(Bytes& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}
void tag(Bytes& out, const char* value) {
    out.insert(out.end(), value, value + 8);
}
void integer(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}
bool nonzero(const Digest& value) { return value != Digest{}; }

struct Reader {
    std::span<const unsigned char> bytes;
    std::size_t at = 0;

    std::span<const unsigned char> take(std::size_t count) {
        need(at <= bytes.size() && count <= bytes.size() - at);
        const auto result = bytes.subspan(at, count);
        at += count;
        return result;
    }
    void magic(const char* expected) {
        const auto raw = take(8);
        need(std::equal(raw.begin(), raw.end(), expected));
    }
    std::uint64_t u64() {
        const auto raw = take(8);
        std::uint64_t result = 0;
        for (unsigned index = 0; index < 8; ++index)
            result |= std::uint64_t(raw[index]) << (8 * index);
        return result;
    }
    Digest fixed_digest() {
        Digest result{};
        const auto raw = take(result.size());
        std::copy(raw.begin(), raw.end(), result.begin());
        return result;
    }
    void end() const { need(at == bytes.size()); }
};

std::array<Digest, SELECTION_FIELDS> selection_fields(const Selection& value) {
    return {value.run, value.trial, value.attempt, value.cohort,
            value.accepted_head, value.owner_contracts[0],
            value.owner_contracts[1], value.owner_contracts[2]};
}

void valid(const Selection& value) {
    const auto fields = selection_fields(value);
    need(std::all_of(fields.begin(), fields.end(),
                     [](const Digest& item) { return nonzero(item); }));
    need(std::set<Digest>(fields.begin(), fields.end()).size() == fields.size());
}

void valid(const Authority& value) {
    const std::array<Digest, 4> pins{
        value.registration, value.service, value.source, value.build};
    need(std::all_of(pins.begin(), pins.end(),
                     [](const Digest& item) { return nonzero(item); }));
    need(std::set<Digest>(pins.begin(), pins.end()).size() == pins.size());
    need(!value.aborted_runs.empty() &&
         std::all_of(value.aborted_runs.begin(), value.aborted_runs.end(),
                     [](const Digest& item) { return nonzero(item); }) &&
         std::is_sorted(value.aborted_runs.begin(), value.aborted_runs.end()) &&
         std::adjacent_find(value.aborted_runs.begin(), value.aborted_runs.end()) ==
             value.aborted_runs.end() &&
         std::binary_search(value.aborted_runs.begin(), value.aborted_runs.end(),
                            mandatory_aborted_run()));
    for (const auto& pin : pins)
        need(!std::binary_search(value.aborted_runs.begin(),
                                 value.aborted_runs.end(), pin));
}

Bytes raw_selection(const Selection& value) {
    valid(value);
    Bytes out;
    for (const auto& field : selection_fields(value)) add(out, field);
    need(out.size() == SELECTION_FIELDS * DIGEST_BYTES);
    return out;
}

Selection parse_selection(std::span<const unsigned char> bytes) {
    need(bytes.size() == SELECTION_FIELDS * DIGEST_BYTES);
    Reader reader{bytes};
    Selection result{};
    result.run = reader.fixed_digest();
    result.trial = reader.fixed_digest();
    result.attempt = reader.fixed_digest();
    result.cohort = reader.fixed_digest();
    result.accepted_head = reader.fixed_digest();
    for (auto& contract : result.owner_contracts)
        contract = reader.fixed_digest();
    reader.end();
    valid(result);
    return result;
}

Bytes authority_bytes(const Authority& value) {
    valid(value);
    Bytes out;
    add(out, "KPB_REGISTERED_IDENTITY_AUTHORITY_V1\n");
    for (const auto* pin : {&value.registration, &value.service,
                            &value.source, &value.build})
        add(out, *pin);
    integer(out, value.aborted_runs.size());
    for (const auto& aborted : value.aborted_runs) add(out, aborted);
    return out;
}

Bytes storage_bytes(const StorageBinding& value) {
    Bytes out;
    add(out, "KPB_REGISTERED_IDENTITY_STORAGE_V1\n");
    for (const auto field : {
             value.journal_directory_device, value.journal_directory_inode,
             value.anchor_directory_device, value.anchor_directory_inode,
             value.journal_device, value.journal_inode,
             value.anchor_device, value.anchor_inode})
        integer(out, field);
    return out;
}

Bytes journal_header(const Authority& authority, const StorageBinding& storage) {
    const auto encoded = authority_bytes(authority);
    const auto encoded_storage = storage_bytes(storage);
    Bytes out;
    tag(out, "KPBIRJ01");
    integer(out, encoded.size());
    add(out, encoded);
    integer(out, encoded_storage.size());
    add(out, encoded_storage);
    add(out, authority_identity(authority));
    add(out, digest(out));
    return out;
}

Digest genesis_checkpoint(const Bytes& header) {
    need(header.size() >= DIGEST_BYTES);
    Digest result{};
    std::copy(header.end() - DIGEST_BYTES, header.end(), result.begin());
    return result;
}

Bytes anchor_header(const Authority& authority, const Digest& genesis) {
    Bytes out;
    tag(out, "KPBIRA01");
    add(out, authority_identity(authority));
    add(out, genesis);
    need(out.size() == ANCHOR_HEADER_BYTES);
    return out;
}

Digest consumed_set_identity(const std::set<Digest>& consumed) {
    Bytes out;
    add(out, "KPB_REGISTERED_IDENTITY_CONSUMED_SET_V1\n");
    integer(out, consumed.size());
    for (const auto& value : consumed) add(out, value);
    return digest(out);
}

void write_all(int fd, std::span<const unsigned char> bytes) {
    std::size_t written = 0;
    while (written < bytes.size()) {
        const auto result = ::write(fd, bytes.data() + written,
                                    bytes.size() - written);
        if (result < 0 && errno == EINTR) continue;
        need(result > 0);
        written += static_cast<std::size_t>(result);
    }
}

void pwrite_all(int fd, std::span<const unsigned char> bytes,
                std::size_t offset) {
    need(offset <= static_cast<std::size_t>(std::numeric_limits<off_t>::max()) &&
         bytes.size() <= static_cast<std::size_t>(std::numeric_limits<off_t>::max()) - offset);
    std::size_t written = 0;
    while (written < bytes.size()) {
        const auto result = ::pwrite(fd, bytes.data() + written,
                                     bytes.size() - written,
                                     static_cast<off_t>(offset + written));
        if (result < 0 && errno == EINTR) continue;
        need(result > 0);
        written += static_cast<std::size_t>(result);
    }
}

Bytes read_at(int fd, std::size_t offset, std::size_t count) {
    need(offset <= static_cast<std::size_t>(std::numeric_limits<off_t>::max()) &&
         count <= static_cast<std::size_t>(std::numeric_limits<off_t>::max()) - offset);
    Bytes result(count);
    std::size_t read = 0;
    while (read < count) {
        const auto got = ::pread(fd, result.data() + read, count - read,
                                 static_cast<off_t>(offset + read));
        if (got < 0 && errno == EINTR) continue;
        need(got > 0);
        read += static_cast<std::size_t>(got);
    }
    return result;
}

std::size_t file_size(int fd) {
    struct stat information {};
    need(::fstat(fd, &information) == 0 && information.st_size >= 0 &&
         static_cast<std::uintmax_t>(information.st_size) <=
             std::numeric_limits<std::size_t>::max());
    return static_cast<std::size_t>(information.st_size);
}

void sync_fd(int fd) {
    int result;
    do { result = ::fsync(fd); } while (result < 0 && errno == EINTR);
    need(result == 0);
}

std::filesystem::path checked_directory(const std::filesystem::path& raw) {
    need(raw.is_absolute() && raw == raw.lexically_normal());
    for (auto current = raw; !current.empty(); current = current.parent_path()) {
        struct stat component {};
        need(::lstat(current.c_str(), &component) == 0 &&
             !S_ISLNK(component.st_mode));
        if (current == current.root_path()) break;
    }
    struct stat information {};
    need(::lstat(raw.c_str(), &information) == 0 &&
         S_ISDIR(information.st_mode) && information.st_uid == ::geteuid() &&
         (information.st_mode & 07777) == 0700);
    return raw;
}

bool inside(const std::filesystem::path& candidate,
            const std::filesystem::path& directory) {
    auto candidate_part = candidate.begin();
    for (auto directory_part = directory.begin();
         directory_part != directory.end(); ++directory_part, ++candidate_part) {
        if (candidate_part == candidate.end() ||
            *candidate_part != *directory_part)
            return false;
    }
    return true;
}

void regular_file(int fd) {
    struct stat information {};
    need(::fstat(fd, &information) == 0 && S_ISREG(information.st_mode) &&
         information.st_uid == ::geteuid() && information.st_nlink == 1 &&
         (information.st_mode & 07777) == 0600);
}

StorageBinding current_storage_binding(int journal_directory_fd,
                                       int anchor_directory_fd,
                                       int journal_fd,
                                       int anchor_fd) {
    struct stat journal_directory {}, anchor_directory {}, journal {}, anchor {};
    need(::fstat(journal_directory_fd, &journal_directory) == 0 &&
         ::fstat(anchor_directory_fd, &anchor_directory) == 0 &&
         ::fstat(journal_fd, &journal) == 0 &&
         ::fstat(anchor_fd, &anchor) == 0 &&
         journal_directory.st_dev != 0 && journal_directory.st_ino != 0 &&
         anchor_directory.st_dev != 0 && anchor_directory.st_ino != 0 &&
         journal.st_dev != 0 && journal.st_ino != 0 &&
         anchor.st_dev != 0 && anchor.st_ino != 0);
    return StorageBinding{
        .journal_directory_device = static_cast<std::uint64_t>(journal_directory.st_dev),
        .journal_directory_inode = static_cast<std::uint64_t>(journal_directory.st_ino),
        .anchor_directory_device = static_cast<std::uint64_t>(anchor_directory.st_dev),
        .anchor_directory_inode = static_cast<std::uint64_t>(anchor_directory.st_ino),
        .journal_device = static_cast<std::uint64_t>(journal.st_dev),
        .journal_inode = static_cast<std::uint64_t>(journal.st_ino),
        .anchor_device = static_cast<std::uint64_t>(anchor.st_dev),
        .anchor_inode = static_cast<std::uint64_t>(anchor.st_ino),
    };
}

void same_directory(const std::filesystem::path& path, int fd) {
    struct stat named {}, opened {};
    need(::lstat(path.c_str(), &named) == 0 && ::fstat(fd, &opened) == 0 &&
         S_ISDIR(named.st_mode) && S_ISDIR(opened.st_mode) &&
         named.st_dev == opened.st_dev && named.st_ino == opened.st_ino);
}

void same_file(int directory_fd, const char* name, int fd) {
    struct stat named {}, opened {};
    need(::fstatat(directory_fd, name, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
         ::fstat(fd, &opened) == 0 && S_ISREG(named.st_mode) &&
         S_ISREG(opened.st_mode) && named.st_dev == opened.st_dev &&
         named.st_ino == opened.st_ino && named.st_uid == ::geteuid() &&
         named.st_nlink == 1 && (named.st_mode & 07777) == 0600);
}

void one_entry(const std::filesystem::path& directory,
               const std::string& expected) {
    std::error_code error;
    std::size_t count = 0;
    for (std::filesystem::directory_iterator it(directory, error), end;
         !error && it != end; it.increment(error)) {
        ++count;
        need(it->path().filename() == expected);
    }
    need(!error && count == 1);
}

struct Exclusive {
    int fd;
    explicit Exclusive(int value) : fd(value) {
        int result;
        do { result = ::flock(fd, LOCK_EX); }
        while (result < 0 && errno == EINTR);
        need(result == 0);
    }
    ~Exclusive() { (void)::flock(fd, LOCK_UN); }
};

struct ParsedState {
    PublicSnapshot snapshot;
    std::set<Digest> consumed;
};
} // namespace

Digest digest(std::span<const unsigned char> bytes) {
    Digest result{};
    unsigned int length = 0;
    need(EVP_Digest(bytes.data(), bytes.size(), result.data(), &length,
                    EVP_sha256(), nullptr) == 1 && length == result.size());
    return result;
}

Digest unhex(const std::string& value) {
    need(value.size() == 64);
    const auto digit = [](char character) -> unsigned {
        if (character >= '0' && character <= '9') return character - '0';
        if (character >= 'a' && character <= 'f') return character - 'a' + 10;
        refuse();
    };
    Digest result{};
    for (std::size_t index = 0; index < result.size(); ++index)
        result[index] = static_cast<unsigned char>(
            (digit(value[2 * index]) << 4) | digit(value[2 * index + 1]));
    return result;
}

std::string hex(const Digest& value) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(value.size() * 2);
    for (const auto byte : value) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 15]);
    }
    return result;
}

Digest mandatory_aborted_run() {
    return unhex("a86414d108d6886768f367a3384fd24de49d4fde7475d8469d92adee29c0e6ab");
}

Digest authority_identity(const Authority& authority) {
    return digest(authority_bytes(authority));
}

Digest selection_identity(const Selection& selection) {
    const auto raw = raw_selection(selection);
    Bytes bytes;
    add(bytes, "KPB_REGISTERED_IDENTITY_SELECTION_V1\n");
    add(bytes, raw);
    return digest(bytes);
}

namespace detail {
struct RegistryCore : std::enable_shared_from_this<RegistryCore> {
    Authority authority;
    std::filesystem::path journal_directory;
    std::filesystem::path anchor_directory;
    int journal_dir_fd = -1;
    int anchor_dir_fd = -1;
    int journal_fd = -1;
    int anchor_fd = -1;
    mutable std::mutex mutex;
    bool poisoned = false;

    ~RegistryCore() {
        for (const int fd : {journal_fd, anchor_fd, journal_dir_fd, anchor_dir_fd})
            if (fd >= 0) (void)::close(fd);
    }

    void identities() const {
        need(!poisoned);
        regular_file(journal_fd);
        regular_file(anchor_fd);
        need(checked_directory(journal_directory) == journal_directory &&
             checked_directory(anchor_directory) == anchor_directory);
        same_directory(journal_directory, journal_dir_fd);
        same_directory(anchor_directory, anchor_dir_fd);
        same_file(journal_dir_fd, "journal.bin", journal_fd);
        same_file(anchor_dir_fd, "latest.bin", anchor_fd);
        one_entry(journal_directory, "journal.bin");
        one_entry(anchor_directory, "latest.bin");
    }

    ParsedState read() const {
        identities();
        const auto storage = current_storage_binding(
            journal_dir_fd, anchor_dir_fd, journal_fd, anchor_fd);
        const auto header = journal_header(authority, storage);
        const auto genesis = genesis_checkpoint(header);
        const auto expected_anchor_header = anchor_header(authority, genesis);
        const auto journal_size = file_size(journal_fd);
        const auto anchor_size = file_size(anchor_fd);
        need(journal_size >= header.size() &&
             (journal_size - header.size()) % EVENT_BYTES == 0 &&
             anchor_size >= expected_anchor_header.size() &&
             (anchor_size - expected_anchor_header.size()) % ANCHOR_ROW_BYTES == 0 &&
             read_at(journal_fd, 0, header.size()) == header &&
             read_at(anchor_fd, 0, expected_anchor_header.size()) ==
                 expected_anchor_header);
        const auto event_count = (journal_size - header.size()) / EVENT_BYTES;
        const auto anchor_count =
            (anchor_size - expected_anchor_header.size()) / ANCHOR_ROW_BYTES;
        need(event_count == anchor_count &&
             event_count <= std::numeric_limits<std::uint64_t>::max());

        ParsedState state{
            .snapshot = PublicSnapshot{
                .authority_identity = identity_registry::authority_identity(authority),
                .sequence = 0,
                .checkpoint = genesis,
                .consumed_set_identity = consumed_set_identity({}),
            },
            .consumed = {},
        };
        const std::set<Digest> aborted(authority.aborted_runs.begin(),
                                       authority.aborted_runs.end());
        for (std::size_t index = 0; index < event_count; ++index) {
            const auto event_offset = header.size() + index * EVENT_BYTES;
            const auto event = read_at(journal_fd, event_offset, EVENT_BYTES);
            Reader reader{event};
            reader.magic("KPBIREV1");
            const auto sequence = reader.u64();
            const auto raw = reader.take(SELECTION_FIELDS * DIGEST_BYTES);
            const auto selection = parse_selection(raw);
            const auto previous = reader.fixed_digest();
            const auto checkpoint = reader.fixed_digest();
            reader.end();
            need(sequence == index + 1 && sequence != 0 &&
                 previous == state.snapshot.checkpoint &&
                 checkpoint == digest(std::span<const unsigned char>(event).first(EVENT_PREFIX_BYTES)));
            for (const auto& field : selection_fields(selection))
                need(!aborted.contains(field) && state.consumed.insert(field).second);

            const auto anchor_row = read_at(
                anchor_fd,
                expected_anchor_header.size() + index * ANCHOR_ROW_BYTES,
                ANCHOR_ROW_BYTES);
            Reader anchor_reader{anchor_row};
            need(anchor_reader.u64() == sequence &&
                 anchor_reader.fixed_digest() == checkpoint);
            anchor_reader.end();
            state.snapshot.sequence = sequence;
            state.snapshot.checkpoint = checkpoint;
        }
        state.snapshot.consumed_set_identity =
            consumed_set_identity(state.consumed);
        identities();
        return state;
    }
};
} // namespace detail

namespace {
std::shared_ptr<detail::RegistryCore> open_core(
    const std::filesystem::path& journal_directory,
    const std::filesystem::path& anchor_directory,
    const Authority& authority,
    bool create) {
    valid(authority);
    auto core = std::make_shared<detail::RegistryCore>();
    core->authority = authority;
    core->journal_directory = checked_directory(journal_directory);
    core->anchor_directory = checked_directory(anchor_directory);
    need(!inside(core->journal_directory, core->anchor_directory) &&
         !inside(core->anchor_directory, core->journal_directory));
    if (create) {
        std::error_code journal_error, anchor_error;
        need(std::filesystem::is_empty(core->journal_directory, journal_error) &&
             !journal_error &&
             std::filesystem::is_empty(core->anchor_directory, anchor_error) &&
             !anchor_error);
    }

    core->journal_dir_fd = ::open(core->journal_directory.c_str(),
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    need(core->journal_dir_fd >= 0);
    core->anchor_dir_fd = ::open(core->anchor_directory.c_str(),
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    need(core->anchor_dir_fd >= 0);
    const int flags = O_RDWR | O_NOFOLLOW | O_CLOEXEC |
        (create ? O_CREAT | O_EXCL : 0);
    core->journal_fd = ::openat(core->journal_dir_fd, "journal.bin", flags, 0600);
    need(core->journal_fd >= 0);
    core->anchor_fd = ::openat(core->anchor_dir_fd, "latest.bin", flags, 0600);
    need(core->anchor_fd >= 0);
    if (create) {
        need(::fchmod(core->journal_fd, 0600) == 0 &&
             ::fchmod(core->anchor_fd, 0600) == 0);
    }
    core->identities();
    if (create) {
        const auto storage = current_storage_binding(
            core->journal_dir_fd, core->anchor_dir_fd,
            core->journal_fd, core->anchor_fd);
        const auto header = journal_header(authority, storage);
        const auto anchor = anchor_header(authority, genesis_checkpoint(header));
        write_all(core->journal_fd, header);
        sync_fd(core->journal_fd);
        write_all(core->anchor_fd, anchor);
        sync_fd(core->anchor_fd);
        sync_fd(core->journal_dir_fd);
        sync_fd(core->anchor_dir_fd);
        core->identities();
    }
    return core;
}
} // namespace

ConsumedIdentity::ConsumedIdentity(std::shared_ptr<detail::RegistryCore> core,
                                   PublicReceipt receipt)
    : core_(std::move(core)), receipt_(std::move(receipt)) {}

Registry::Registry(std::shared_ptr<detail::RegistryCore> core)
    : core_(std::move(core)) {}

#ifdef KPI_REGISTERED_IDENTITY_UNFUNDED_SETUP
Registry Registry::initialize_fresh_unfunded(
    const std::filesystem::path& journal_directory,
    const std::filesystem::path& trusted_anchor_directory,
    const Authority& authority) {
    auto core = open_core(journal_directory, trusted_anchor_directory,
                          authority, true);
    {
        std::lock_guard guard(core->mutex);
        Exclusive lock(core->journal_fd);
        (void)core->read();
    }
    return Registry(std::move(core));
}
#endif

Registry Registry::open_existing(
    const std::filesystem::path& journal_directory,
    const std::filesystem::path& trusted_anchor_directory,
    const Authority& authority) {
    auto core = open_core(journal_directory, trusted_anchor_directory,
                          authority, false);
    {
        std::lock_guard guard(core->mutex);
        Exclusive lock(core->journal_fd);
        (void)core->read();
    }
    return Registry(std::move(core));
}

PublicSnapshot Registry::snapshot() const {
    std::lock_guard guard(core_->mutex);
    Exclusive lock(core_->journal_fd);
    return core_->read().snapshot;
}

ConsumedIdentity Registry::consume(const Selection& selection,
                                   FailureOnlyHook hook) {
    valid(selection);
    std::lock_guard guard(core_->mutex);
    Exclusive lock(core_->journal_fd);
    const auto prior = core_->read();
    const std::set<Digest> aborted(core_->authority.aborted_runs.begin(),
                                   core_->authority.aborted_runs.end());
    for (const auto& field : selection_fields(selection))
        need(!aborted.contains(field) && !prior.consumed.contains(field));
    need(prior.snapshot.sequence != std::numeric_limits<std::uint64_t>::max());

    Bytes event;
    tag(event, "KPBIREV1");
    integer(event, prior.snapshot.sequence + 1);
    add(event, raw_selection(selection));
    add(event, prior.snapshot.checkpoint);
    need(event.size() == EVENT_PREFIX_BYTES);
    const auto checkpoint = digest(event);
    add(event, checkpoint);
    need(event.size() == EVENT_BYTES);

    Bytes anchor_row;
    integer(anchor_row, prior.snapshot.sequence + 1);
    add(anchor_row, checkpoint);
    need(anchor_row.size() == ANCHOR_ROW_BYTES);

    try {
        core_->identities();
        const auto journal_offset = file_size(core_->journal_fd);
        const auto anchor_offset = file_size(core_->anchor_fd);
        pwrite_all(core_->journal_fd, event, journal_offset);
        if (hook) hook(WriteBoundary::JournalWritten);
        sync_fd(core_->journal_fd);
        if (hook) hook(WriteBoundary::JournalSynced);
        pwrite_all(core_->anchor_fd, anchor_row, anchor_offset);
        if (hook) hook(WriteBoundary::AnchorWritten);
        sync_fd(core_->anchor_fd);
        if (hook) hook(WriteBoundary::AnchorSynced);
        core_->identities();
        const auto after = core_->read();
        need(after.snapshot.sequence == prior.snapshot.sequence + 1 &&
             after.snapshot.checkpoint == checkpoint);
        PublicReceipt receipt{
            .authority_identity = after.snapshot.authority_identity,
            .selection_identity = identity_registry::selection_identity(selection),
            .sequence = after.snapshot.sequence,
            .checkpoint = after.snapshot.checkpoint,
            .consumed_set_identity = after.snapshot.consumed_set_identity,
        };
        return ConsumedIdentity(core_, receipt);
    } catch (...) {
        core_->poisoned = true;
        refuse();
    }
}

SourceStatus source_status() {
    return SourceStatus{
        .schema = "kpb-registered-identity-registry-source-only/v1",
        .status = "UNQUALIFIED_SOURCE_ONLY",
        .trial03_retrofit_allowed = false,
        .trusted_anchor_required = true,
        .coordinated_anchor_rollback_in_scope = false,
        .direct_accepted_head_integration = false,
        .selected_configured_build_integration = false,
        .one_shot_private_intake_integration = false,
        .registered_driver_configured = false,
        .launch_authorized = false,
    };
}

} // namespace kpi::mpc::financial::identity_registry
