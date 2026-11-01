#include "v3_native_authority.hpp"

#include "privacy_measurement_run_binding_wire.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <map>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <poll.h>
#include <set>
#include <string_view>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace kpb::future_recipient::v3_native {
namespace {

using Bytes = std::vector<unsigned char>;
namespace wire = measurement::wire;

constexpr std::size_t JOURNAL_HEADER_BYTES = 40;
constexpr std::size_t HEAD_HEADER_BYTES = 104;
constexpr std::size_t EVENT_BODY_BYTES = 297;
constexpr std::size_t EVENT_BYTES = 329;
constexpr std::size_t HEAD_ROW_BODY_BYTES = 48;
constexpr std::size_t HEAD_ROW_BYTES = 80;
constexpr std::size_t EXTERNAL_HEAD_HEADER_BODY_BYTES = 72;
constexpr std::size_t EXTERNAL_HEAD_HEADER_BYTES = 104;
constexpr std::size_t EXTERNAL_HEAD_ROW_BODY_BYTES = 112;
constexpr std::size_t EXTERNAL_HEAD_ROW_BYTES = 144;
constexpr int REQUIRED_SEALS =
    F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
constexpr std::string_view JOURNAL_MAGIC = "KPV3LG01";
constexpr std::string_view HEAD_MAGIC = "KPV3HD01";
constexpr std::string_view EVENT_MAGIC = "KPV3EV01";
constexpr std::string_view HEAD_ROW_MAGIC = "KPV3HR01";
constexpr std::string_view EXTERNAL_HEAD_MAGIC = "KPV3XH01";
constexpr std::string_view EXTERNAL_HEAD_ROW_MAGIC = "KPV3XR01";
constexpr std::string_view ACK_MAGIC = "KPV3ACK1";
constexpr std::string_view INVOICE_MAGIC = "KPX3IN01";

void need(bool good) {
    if (!good) throw NativeRefused();
}

void close_fd(int& fd) {
    if (fd >= 0) (void)::close(fd);
    fd = -1;
}

bool nonzero(const Digest& value) { return value != Digest{}; }

void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}

void add(Bytes& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}

void add_u64(Bytes& out, std::uint64_t value) {
    for (unsigned index = 0; index < 8; ++index)
        out.push_back(static_cast<unsigned char>(value >> (8 * index)));
}

std::uint64_t read_u64(std::span<const unsigned char> value) {
    need(value.size() == 8);
    std::uint64_t result = 0;
    for (unsigned index = 0; index < 8; ++index)
        result |= std::uint64_t(value[index]) << (8 * index);
    return result;
}

Digest sha256(std::span<const unsigned char> value) {
    Digest result{};
    unsigned int length = 0;
    need(EVP_Digest(value.data(), value.size(), result.data(), &length,
                    EVP_sha256(), nullptr) == 1 &&
         length == result.size());
    return result;
}

Digest mac(const Digest& key, std::span<const unsigned char> value) {
    Digest result{};
    std::size_t length = 0;
    need(EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA256", nullptr,
                   key.data(), key.size(), value.data(), value.size(),
                   result.data(), result.size(), &length) != nullptr &&
         length == result.size());
    return result;
}

bool equal(const Digest& left, const Digest& right) {
    return CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0;
}

Digest binding_identity(const measurement::RunBinding& binding) {
    try {
        measurement::validate_measurement_run_binding(binding);
        const auto bytes = wire::canonical_run_binding_bytes(binding);
        return sha256(bytes);
    } catch (...) {
        throw NativeRefused();
    }
}

std::uint64_t invoice_index(const Invoice208& invoice) {
    need(std::equal(INVOICE_MAGIC.begin(), INVOICE_MAGIC.end(),
                    invoice.begin()));
    return read_u64(std::span(invoice).subspan(40, 8));
}

void write_all_at(int fd, std::span<const unsigned char> value,
                  std::uint64_t offset) {
    need(offset <= static_cast<std::uint64_t>(
                       std::numeric_limits<off_t>::max()) &&
         value.size() <= static_cast<std::uint64_t>(
                            std::numeric_limits<off_t>::max()) - offset);
    std::size_t at = 0;
    while (at < value.size()) {
        const auto count = ::pwrite(
            fd, value.data() + at, value.size() - at,
            static_cast<off_t>(offset + at));
        if (count < 0 && errno == EINTR) continue;
        need(count > 0);
        at += static_cast<std::size_t>(count);
    }
}

Bytes read_all_at(int fd, std::uint64_t offset, std::size_t size) {
    need(offset <= static_cast<std::uint64_t>(
                       std::numeric_limits<off_t>::max()) &&
         size <= static_cast<std::uint64_t>(
                     std::numeric_limits<off_t>::max()) - offset);
    Bytes result(size);
    std::size_t at = 0;
    while (at < size) {
        const auto count = ::pread(
            fd, result.data() + at, size - at,
            static_cast<off_t>(offset + at));
        if (count < 0 && errno == EINTR) continue;
        need(count > 0);
        at += static_cast<std::size_t>(count);
    }
    return result;
}

std::uint64_t file_size(int fd) {
    struct stat state{};
    need(::fstat(fd, &state) == 0 && state.st_size >= 0);
    return static_cast<std::uint64_t>(state.st_size);
}

void sync_fd(int fd) {
    int result = -1;
    do { result = ::fsync(fd); } while (result < 0 && errno == EINTR);
    need(result == 0);
}

void require_cloexec(int fd) {
    const int flags = ::fcntl(fd, F_GETFD);
    need(flags >= 0 && (flags & FD_CLOEXEC) != 0);
}

void require_sealed_file(int fd, std::size_t size, mode_t mode,
                         bool require_close_on_exec = true) {
    struct stat state{};
    need(fd >= 0 && ::fstat(fd, &state) == 0 && S_ISREG(state.st_mode) &&
         state.st_uid == ::geteuid() &&
         (state.st_mode & 0777) == mode &&
         state.st_size == static_cast<off_t>(size) &&
         (::fcntl(fd, F_GET_SEALS) & REQUIRED_SEALS) == REQUIRED_SEALS);
    if (require_close_on_exec) require_cloexec(fd);
}

int sealed_memfd(std::string_view name,
                 std::span<const unsigned char> value) {
    int fd = ::memfd_create(std::string(name).c_str(),
                            MFD_CLOEXEC | MFD_ALLOW_SEALING);
    need(fd >= 0);
    try {
        need(::fchmod(fd, 0400) == 0);
        write_all_at(fd, value, 0);
        need(::fcntl(fd, F_ADD_SEALS, REQUIRED_SEALS) == 0 &&
             (::fcntl(fd, F_GET_SEALS) & REQUIRED_SEALS) == REQUIRED_SEALS);
        return fd;
    } catch (...) {
        close_fd(fd);
        throw;
    }
}

Digest read_key(int fd) {
    require_sealed_file(fd, 32, 0600);
    const auto bytes = read_all_at(fd, 0, 32);
    Digest result{};
    std::copy(bytes.begin(), bytes.end(), result.begin());
    need(nonzero(result));
    return result;
}

#ifdef KPB_V3_NATIVE_AUTHORITY_TEST_SETUP
int sealed_key_fd(const Digest& key) {
    need(nonzero(key));
    int fd = ::memfd_create("kpb-v3-ledger-key",
                            MFD_CLOEXEC | MFD_ALLOW_SEALING);
    need(fd >= 0);
    try {
        need(::fchmod(fd, 0600) == 0);
        write_all_at(fd, key, 0);
        need(::fcntl(fd, F_ADD_SEALS, REQUIRED_SEALS) == 0);
        return fd;
    } catch (...) {
        close_fd(fd);
        throw;
    }
}
#endif

Digest ack_digest(const Digest& challenge,
                  std::span<const unsigned char> binding,
                  const Invoice208& invoice) {
    Bytes bytes;
    bytes.reserve(ACK_MAGIC.size() + challenge.size() + binding.size() +
                  invoice.size());
    add(bytes, ACK_MAGIC);
    add(bytes, challenge);
    add(bytes, binding);
    add(bytes, invoice);
    return sha256(bytes);
}

void send_exact(int fd, std::span<const unsigned char> value) {
    const auto sent = ::send(fd, value.data(), value.size(), MSG_NOSIGNAL);
    need(sent == static_cast<ssize_t>(value.size()));
}

Bytes receive_packet(int fd, std::size_t expected, int timeout_ms) {
    pollfd selected{.fd = fd, .events = POLLIN, .revents = 0};
    int ready = -1;
    do { ready = ::poll(&selected, 1, timeout_ms); }
    while (ready < 0 && errno == EINTR);
    need(ready == 1 && (selected.revents & POLLIN) != 0);
    Bytes bytes(expected + 1);
    const auto count = ::recv(fd, bytes.data(), bytes.size(), 0);
    need(count == static_cast<ssize_t>(expected));
    bytes.resize(expected);
    return bytes;
}

std::array<std::uint64_t, 2> identity(int fd) {
    struct stat state{};
    need(::fstat(fd, &state) == 0);
    return {static_cast<std::uint64_t>(state.st_dev),
            static_cast<std::uint64_t>(state.st_ino)};
}

void clear_cloexec(int fd) {
    const int flags = ::fcntl(fd, F_GETFD);
    need(flags >= 0 && ::fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC) == 0);
}

int duplicate_high(int fd) {
    const int result = ::fcntl(fd, F_DUPFD_CLOEXEC, 64);
    need(result >= 64);
    return result;
}

} // namespace

namespace detail {

struct ExternalHeadCore {
    Digest binding_id{};
    int directory_fd{-1};
    int head_fd{-1};
    int key_fd{-1};
    std::array<std::uint64_t, 2> directory_identity{};
    std::array<std::uint64_t, 2> head_identity{};
    std::uint64_t sequence{};
    Digest local_head{};
    Digest row_chain{};
    bool poisoned{};

    ~ExternalHeadCore() {
        close_fd(directory_fd);
        close_fd(head_fd);
        close_fd(key_fd);
    }

    void identities() const {
        need(!poisoned);
        struct stat directory{}, named{}, opened{};
        need(::fstat(directory_fd, &directory) == 0 &&
             S_ISDIR(directory.st_mode) &&
             directory.st_uid == ::geteuid() &&
             (directory.st_mode & 0777) == 0700 &&
             identity(directory_fd) == directory_identity &&
             ::fstat(head_fd, &opened) == 0 &&
             S_ISREG(opened.st_mode) && opened.st_uid == ::geteuid() &&
             opened.st_nlink == 1 && (opened.st_mode & 0777) == 0600 &&
             identity(head_fd) == head_identity &&
             ::fstatat(directory_fd, "latest-head.bin", &named,
                       AT_SYMLINK_NOFOLLOW) == 0 &&
             named.st_dev == opened.st_dev && named.st_ino == opened.st_ino);
        require_cloexec(directory_fd);
        require_cloexec(head_fd);
        (void)read_key(key_fd);
    }

    Digest genesis() const {
        Bytes header;
        add(header, JOURNAL_MAGIC);
        add(header, binding_id);
        need(header.size() == JOURNAL_HEADER_BYTES);
        return sha256(header);
    }

    Bytes header(const Digest& key) const {
        Bytes result;
        add(result, EXTERNAL_HEAD_MAGIC);
        add(result, binding_id);
        add(result, genesis());
        need(result.size() == EXTERNAL_HEAD_HEADER_BODY_BYTES);
        add(result, mac(key, result));
        need(result.size() == EXTERNAL_HEAD_HEADER_BYTES);
        return result;
    }

    void scan() {
        identities();
        const auto key = read_key(key_fd);
        const auto start = header(key);
        need(file_size(head_fd) >= EXTERNAL_HEAD_HEADER_BYTES &&
             read_all_at(head_fd, 0, EXTERNAL_HEAD_HEADER_BYTES) == start);
        sequence = 0;
        local_head = genesis();
        row_chain = sha256(start);
        std::uint64_t at = EXTERNAL_HEAD_HEADER_BYTES;
        while (at < file_size(head_fd)) {
            need(sequence != std::numeric_limits<std::uint64_t>::max() &&
                 file_size(head_fd) - at >= EXTERNAL_HEAD_ROW_BYTES);
            const auto row = read_all_at(
                head_fd, at, EXTERNAL_HEAD_ROW_BYTES);
            need(std::equal(EXTERNAL_HEAD_ROW_MAGIC.begin(),
                            EXTERNAL_HEAD_ROW_MAGIC.end(), row.begin()) &&
                 read_u64(std::span(row).subspan(8, 8)) == sequence + 1);
            Digest supplied_head{}, supplied_previous{}, supplied_binding{},
                supplied_mac{};
            std::copy_n(row.begin() + 16, 32, supplied_head.begin());
            std::copy_n(row.begin() + 48, 32, supplied_previous.begin());
            std::copy_n(row.begin() + 80, 32, supplied_binding.begin());
            std::copy_n(row.begin() + EXTERNAL_HEAD_ROW_BODY_BYTES, 32,
                        supplied_mac.begin());
            need(nonzero(supplied_head) && equal(supplied_previous, row_chain) &&
                 equal(supplied_binding, binding_id) &&
                 equal(supplied_mac,
                       mac(key, std::span(row).first(
                           EXTERNAL_HEAD_ROW_BODY_BYTES))));
            sequence += 1;
            local_head = supplied_head;
            row_chain = sha256(row);
            at += EXTERNAL_HEAD_ROW_BYTES;
        }
        need(at == file_size(head_fd));
    }

    void append(std::uint64_t next_sequence, const Digest& next_local_head,
                const FailureOnlyHook& hook) {
        try {
            identities();
            need(next_sequence == sequence + 1 &&
                 sequence < (std::numeric_limits<std::uint64_t>::max() -
                             EXTERNAL_HEAD_HEADER_BYTES) /
                                EXTERNAL_HEAD_ROW_BYTES &&
                 nonzero(next_local_head));
            const auto key = read_key(key_fd);
            Bytes row;
            row.reserve(EXTERNAL_HEAD_ROW_BYTES);
            add(row, EXTERNAL_HEAD_ROW_MAGIC);
            add_u64(row, next_sequence);
            add(row, next_local_head);
            add(row, row_chain);
            add(row, binding_id);
            need(row.size() == EXTERNAL_HEAD_ROW_BODY_BYTES);
            add(row, mac(key, row));
            need(row.size() == EXTERNAL_HEAD_ROW_BYTES);
            const auto at = EXTERNAL_HEAD_HEADER_BYTES +
                sequence * EXTERNAL_HEAD_ROW_BYTES;
            need(file_size(head_fd) == at);
            write_all_at(head_fd, row, at);
            if (hook) hook(DurableBoundary::ExternalHeadWritten);
            sync_fd(head_fd);
            if (hook) hook(DurableBoundary::ExternalHeadSynced);
            sync_fd(directory_fd);
            if (hook) hook(DurableBoundary::ExternalDirectorySynced);
            sequence = next_sequence;
            local_head = next_local_head;
            row_chain = sha256(row);
        } catch (...) {
            poisoned = true;
            throw;
        }
    }
};

struct ParentCore {
    measurement::RunBinding binding;
    Digest binding_id{};
    int directory_fd{-1};
    int journal_fd{-1};
    int heads_fd{-1};
    int key_fd{-1};
    std::array<std::uint64_t, 2> directory_identity{};
    std::array<std::uint64_t, 2> journal_identity{};
    std::array<std::uint64_t, 2> heads_identity{};
    std::uint64_t sequence{};
    Digest head{};
    std::map<std::uint64_t, LifecycleState> states;
    std::map<std::uint64_t, Invoice208> invoices;
    std::unique_ptr<ExternalHeadCore> external_head;
    bool poisoned{};

    ~ParentCore() {
        close_fd(directory_fd);
        close_fd(journal_fd);
        close_fd(heads_fd);
        close_fd(key_fd);
    }

    void identities() const {
        need(!poisoned);
        struct stat directory{};
        need(::fstat(directory_fd, &directory) == 0 &&
             S_ISDIR(directory.st_mode) && directory.st_uid == ::geteuid() &&
             (directory.st_mode & 0777) == 0700 &&
             identity(directory_fd) == directory_identity);
        for (const auto& selected : {
                 std::pair{journal_fd, journal_identity},
                 std::pair{heads_fd, heads_identity}}) {
            struct stat state{};
            need(::fstat(selected.first, &state) == 0 &&
                 S_ISREG(state.st_mode) && state.st_uid == ::geteuid() &&
                 state.st_nlink == 1 && (state.st_mode & 0777) == 0600 &&
                 identity(selected.first) == selected.second);
            require_cloexec(selected.first);
        }
        struct stat named{}, opened{};
        need(::fstatat(directory_fd, "journal.bin", &named,
                       AT_SYMLINK_NOFOLLOW) == 0 &&
             ::fstat(journal_fd, &opened) == 0 &&
             named.st_dev == opened.st_dev && named.st_ino == opened.st_ino &&
             ::fstatat(directory_fd, "heads.bin", &named,
                       AT_SYMLINK_NOFOLLOW) == 0 &&
             ::fstat(heads_fd, &opened) == 0 &&
             named.st_dev == opened.st_dev && named.st_ino == opened.st_ino);
        require_cloexec(directory_fd);
        (void)read_key(key_fd);
    }

    Bytes journal_header() const {
        Bytes result;
        add(result, JOURNAL_MAGIC);
        add(result, binding_id);
        need(result.size() == JOURNAL_HEADER_BYTES);
        return result;
    }

    Bytes head_header(const Digest& key, const Digest& genesis) const {
        Bytes body;
        add(body, HEAD_MAGIC);
        add(body, binding_id);
        add(body, genesis);
        need(body.size() == HEAD_HEADER_BYTES - 32);
        const auto authentication = mac(key, body);
        add(body, authentication);
        need(body.size() == HEAD_HEADER_BYTES);
        return body;
    }

    void scan(const Digest& latest_binding, std::uint64_t latest_sequence,
              const Digest& latest_head) {
        identities();
        const auto key = read_key(key_fd);
        const auto journal_start = journal_header();
        need(file_size(journal_fd) >= JOURNAL_HEADER_BYTES &&
             read_all_at(journal_fd, 0, JOURNAL_HEADER_BYTES) == journal_start);
        const auto genesis = sha256(journal_start);
        const auto head_start = head_header(key, genesis);
        need(file_size(heads_fd) >= HEAD_HEADER_BYTES &&
             read_all_at(heads_fd, 0, HEAD_HEADER_BYTES) == head_start);

        sequence = 0;
        head = genesis;
        states.clear();
        invoices.clear();
        std::uint64_t journal_at = JOURNAL_HEADER_BYTES;
        std::uint64_t heads_at = HEAD_HEADER_BYTES;
        while (journal_at < file_size(journal_fd)) {
            need(sequence != std::numeric_limits<std::uint64_t>::max());
            need(file_size(journal_fd) - journal_at >= EVENT_BYTES &&
                 file_size(heads_fd) - heads_at >= HEAD_ROW_BYTES);
            const auto event = read_all_at(journal_fd, journal_at, EVENT_BYTES);
            need(std::equal(EVENT_MAGIC.begin(), EVENT_MAGIC.end(),
                            event.begin()));
            const auto event_sequence = read_u64(
                std::span(event).subspan(8, 8));
            const auto state_raw = event[16];
            const auto index = read_u64(std::span(event).subspan(17, 8));
            Digest previous{}, event_binding{}, supplied_mac{};
            std::copy_n(event.begin() + 25, 32, previous.begin());
            std::copy_n(event.begin() + 57, 32, event_binding.begin());
            Invoice208 invoice{};
            std::copy_n(event.begin() + 89, invoice.size(), invoice.begin());
            std::copy_n(event.begin() + EVENT_BODY_BYTES, 32,
                        supplied_mac.begin());
            need(event_sequence == sequence + 1 && equal(previous, head) &&
                 equal(event_binding, binding_id) &&
                 equal(supplied_mac,
                       mac(key, std::span(event).first(EVENT_BODY_BYTES))) &&
                 invoice_index(invoice) == index &&
                 state_raw >= static_cast<unsigned char>(
                                  LifecycleState::Allocated) &&
                 state_raw <= static_cast<unsigned char>(
                                  LifecycleState::Poisoned));
            const auto state = static_cast<LifecycleState>(state_raw);
            const auto prior = states.find(index);
            if (state == LifecycleState::Allocated) {
                need(prior == states.end());
                invoices.emplace(index, invoice);
            } else {
                need(prior != states.end() && invoices.at(index) == invoice);
                const auto allowed =
                    (state == LifecycleState::Exported &&
                     prior->second == LifecycleState::Allocated) ||
                    (state == LifecycleState::Accepted &&
                     prior->second == LifecycleState::Exported) ||
                    (state == LifecycleState::Consumed &&
                     prior->second == LifecycleState::Accepted) ||
                    (state == LifecycleState::Poisoned &&
                     prior->second != LifecycleState::Poisoned);
                need(allowed);
            }
            const auto event_head = sha256(event);
            const auto row = read_all_at(heads_fd, heads_at, HEAD_ROW_BYTES);
            need(std::equal(HEAD_ROW_MAGIC.begin(), HEAD_ROW_MAGIC.end(),
                            row.begin()) &&
                 read_u64(std::span(row).subspan(8, 8)) == event_sequence);
            Digest row_head{}, row_mac{};
            std::copy_n(row.begin() + 16, 32, row_head.begin());
            std::copy_n(row.begin() + HEAD_ROW_BODY_BYTES, 32,
                        row_mac.begin());
            need(equal(row_head, event_head) &&
                 equal(row_mac,
                       mac(key, std::span(row).first(HEAD_ROW_BODY_BYTES))));
            states[index] = state;
            sequence = event_sequence;
            head = event_head;
            journal_at += EVENT_BYTES;
            heads_at += HEAD_ROW_BYTES;
        }
        need(journal_at == file_size(journal_fd) &&
             heads_at == file_size(heads_fd) &&
             equal(latest_binding, binding_id) &&
             latest_sequence == sequence && equal(latest_head, head));
    }

    void append(LifecycleState state, std::uint64_t index,
                const Invoice208& invoice, FailureOnlyHook hook) {
        try {
            identities();
            need(sequence <
                     (std::numeric_limits<std::uint64_t>::max() -
                      JOURNAL_HEADER_BYTES) / EVENT_BYTES &&
                 sequence <
                     (std::numeric_limits<std::uint64_t>::max() -
                      HEAD_HEADER_BYTES) / HEAD_ROW_BYTES);
            const auto key = read_key(key_fd);
            Bytes event;
            event.reserve(EVENT_BYTES);
            add(event, EVENT_MAGIC);
            add_u64(event, sequence + 1);
            event.push_back(static_cast<unsigned char>(state));
            add_u64(event, index);
            add(event, head);
            add(event, binding_id);
            add(event, invoice);
            need(event.size() == EVENT_BODY_BYTES);
            add(event, mac(key, event));
            need(event.size() == EVENT_BYTES);
            const auto next_head = sha256(event);

            Bytes row;
            row.reserve(HEAD_ROW_BYTES);
            add(row, HEAD_ROW_MAGIC);
            add_u64(row, sequence + 1);
            add(row, next_head);
            need(row.size() == HEAD_ROW_BODY_BYTES);
            add(row, mac(key, row));
            need(row.size() == HEAD_ROW_BYTES);

            const auto journal_at = JOURNAL_HEADER_BYTES +
                sequence * EVENT_BYTES;
            const auto heads_at = HEAD_HEADER_BYTES +
                sequence * HEAD_ROW_BYTES;
            need(file_size(journal_fd) == journal_at &&
                 file_size(heads_fd) == heads_at);
            write_all_at(journal_fd, event, journal_at);
            if (hook) hook(DurableBoundary::JournalWritten);
            sync_fd(journal_fd);
            if (hook) hook(DurableBoundary::JournalSynced);
            write_all_at(heads_fd, row, heads_at);
            if (hook) hook(DurableBoundary::HeadWritten);
            sync_fd(heads_fd);
            if (hook) hook(DurableBoundary::HeadSynced);
            sync_fd(directory_fd);
            if (hook) hook(DurableBoundary::DirectorySynced);

            if (external_head != nullptr)
                external_head->append(sequence + 1, next_head, hook);

            sequence += 1;
            head = next_head;
            states[index] = state;
            invoices[index] = invoice;
        } catch (...) {
            poisoned = true;
            throw;
        }
    }
};

} // namespace detail

Digest recompute_v3_run_binding_identity(
        const measurement::RunBinding& binding) {
    return binding_identity(binding);
}

NativeRefused::NativeRefused()
    : std::runtime_error("V3 native authority refused") {}

InvoiceMaterialAuthority::InvoiceMaterialAuthority(
        Invoice208 invoice, Digest binding, Digest accepted_history,
        Digest parent_instance, Digest source_generation)
    : invoice_(invoice), binding_identity_(binding),
      accepted_history_identity_(accepted_history),
      parent_instance_identity_(parent_instance),
      source_generation_identity_(source_generation) {
    need(nonzero(binding_identity_) && nonzero(accepted_history_identity_) &&
         nonzero(parent_instance_identity_) &&
         nonzero(source_generation_identity_) &&
         binding_identity_ != accepted_history_identity_);
    (void)invoice_index(invoice_);
}

InvoiceMaterialAuthority::InvoiceMaterialAuthority(
        InvoiceMaterialAuthority&& other) noexcept
    : invoice_(other.invoice_), binding_identity_(other.binding_identity_),
      accepted_history_identity_(other.accepted_history_identity_),
      parent_instance_identity_(other.parent_instance_identity_),
      source_generation_identity_(other.source_generation_identity_),
      live_(other.live_.exchange(false)) {}

#ifdef KPB_V3_NATIVE_AUTHORITY_TEST_SETUP
InvoiceMaterialAuthority InvoiceMaterialAuthority::test_only_mint(
        ParentV3Authority& parent, Invoice208 invoice) {
    need(nonzero(parent.binding_identity_) &&
         nonzero(parent.accepted_history_identity_) &&
         nonzero(parent.instance_identity_));
    const auto source_generation = sha256(invoice);
    need(nonzero(source_generation));
    return InvoiceMaterialAuthority(
        invoice, parent.binding_identity_, parent.accepted_history_identity_,
        parent.instance_identity_, source_generation);
}
#endif

LatestHeadAuthority::LatestHeadAuthority(
        Digest binding, std::uint64_t sequence, Digest head)
    : binding_identity_(binding), sequence_(sequence), head_(head) {
    need(nonzero(binding_identity_) && nonzero(head_));
}

LatestHeadAuthority::LatestHeadAuthority(LatestHeadAuthority&& other) noexcept
    : binding_identity_(other.binding_identity_), sequence_(other.sequence_),
      head_(other.head_), live_(other.live_.exchange(false)) {}

ExternalLatestHeadUpdaterAuthority::ExternalLatestHeadUpdaterAuthority(
        std::unique_ptr<detail::ExternalHeadCore> core)
    : core_(std::move(core)) {
    need(core_ != nullptr && !core_->poisoned && nonzero(core_->binding_id) &&
         nonzero(core_->local_head));
}

ExternalLatestHeadUpdaterAuthority::ExternalLatestHeadUpdaterAuthority(
        ExternalLatestHeadUpdaterAuthority&& other) noexcept
    : core_(std::move(other.core_)) {}

ExternalLatestHeadUpdaterAuthority::~ExternalLatestHeadUpdaterAuthority() =
    default;

V3LifecycleControllerAuthority::V3LifecycleControllerAuthority(
        Digest binding, Digest history,
        ExternalLatestHeadUpdaterAuthority&& updater)
    : binding_identity_(binding), accepted_history_identity_(history),
      updater_(std::move(updater)) {
    need(nonzero(binding_identity_) && nonzero(accepted_history_identity_) &&
         binding_identity_ != accepted_history_identity_ &&
         updater_.core_ != nullptr &&
         equal(updater_.core_->binding_id, binding_identity_));
}

V3LifecycleControllerAuthority::V3LifecycleControllerAuthority(
        V3LifecycleControllerAuthority&& other) noexcept
    : binding_identity_(other.binding_identity_),
      accepted_history_identity_(other.accepted_history_identity_),
      updater_(std::move(other.updater_)),
      live_(other.live_.exchange(false)) {}

#ifdef KPB_V3_NATIVE_AUTHORITY_TEST_SETUP
LatestHeadAuthority LatestHeadAuthority::test_only_mint(
        const measurement::RunBinding& binding, std::uint64_t sequence,
        Digest head) {
    return LatestHeadAuthority(binding_identity(binding), sequence, head);
}
#endif

ParentLedgerDescriptorsAuthority::ParentLedgerDescriptorsAuthority(
        int directory, int journal, int heads, int key)
    : directory_fd_(directory), journal_fd_(journal), heads_fd_(heads),
      mac_key_fd_(key) {
    need(directory_fd_ >= 0 && journal_fd_ >= 0 && heads_fd_ >= 0 &&
         mac_key_fd_ >= 0);
}

ParentLedgerDescriptorsAuthority::ParentLedgerDescriptorsAuthority(
        ParentLedgerDescriptorsAuthority&& other) noexcept
    : directory_fd_(other.directory_fd_), journal_fd_(other.journal_fd_),
      heads_fd_(other.heads_fd_), mac_key_fd_(other.mac_key_fd_),
      live_(other.live_.exchange(false)) {
    other.directory_fd_ = other.journal_fd_ = other.heads_fd_ =
        other.mac_key_fd_ = -1;
}

ParentLedgerDescriptorsAuthority::~ParentLedgerDescriptorsAuthority() {
    close_fd(directory_fd_);
    close_fd(journal_fd_);
    close_fd(heads_fd_);
    close_fd(mac_key_fd_);
}

AllocatedInvoiceAuthority::AllocatedInvoiceAuthority(
        ParentV3Authority* parent, Digest parent_instance,
        Digest source_generation, std::uint64_t index, Invoice208 invoice)
    : parent_(parent), parent_instance_identity_(parent_instance),
      source_generation_identity_(source_generation), index_(index),
      invoice_(invoice) {
    need(parent_ != nullptr && nonzero(parent_instance_identity_) &&
         nonzero(source_generation_identity_) &&
         invoice_index(invoice_) == index_);
}

AllocatedInvoiceAuthority::AllocatedInvoiceAuthority(
        AllocatedInvoiceAuthority&& other) noexcept
    : parent_(other.parent_),
      parent_instance_identity_(other.parent_instance_identity_),
      source_generation_identity_(other.source_generation_identity_),
      index_(other.index_), invoice_(other.invoice_),
      live_(other.live_.exchange(false)) {}

OwnerOfferAuthority::OwnerOfferAuthority(int invoice, int binding,
                                         int capability)
    : invoice_fd_(invoice), binding_fd_(binding), capability_fd_(capability) {
    try {
        require_sealed_file(invoice_fd_, 208, 0400);
        require_sealed_file(binding_fd_, wire::RUN_BINDING_BYTES, 0400);
        struct stat socket_state{};
        need(::fstat(capability_fd_, &socket_state) == 0 &&
             S_ISSOCK(socket_state.st_mode));
        require_cloexec(capability_fd_);
        const auto invoice_id = identity(invoice_fd_);
        const auto binding_id = identity(binding_fd_);
        const auto capability_id = identity(capability_fd_);
        identities_ = {invoice_id[0], invoice_id[1], binding_id[0],
                       binding_id[1], capability_id[0], capability_id[1]};
    } catch (...) {
        close_fd(invoice_fd_);
        close_fd(binding_fd_);
        close_fd(capability_fd_);
        throw;
    }
}

OwnerOfferAuthority::OwnerOfferAuthority(OwnerOfferAuthority&& other) noexcept
    : invoice_fd_(other.invoice_fd_), binding_fd_(other.binding_fd_),
      capability_fd_(other.capability_fd_), identities_(other.identities_),
      live_(other.live_.exchange(false)) {
    other.invoice_fd_ = other.binding_fd_ = other.capability_fd_ = -1;
}

OwnerOfferAuthority::~OwnerOfferAuthority() {
    close_fd(invoice_fd_);
    close_fd(binding_fd_);
    close_fd(capability_fd_);
}

void OwnerOfferAuthority::install_for_owner() && {
    need(live_.exchange(false));
    require_sealed_file(invoice_fd_, 208, 0400);
    require_sealed_file(binding_fd_, wire::RUN_BINDING_BYTES, 0400);
    need(identity(invoice_fd_) ==
             std::array<std::uint64_t, 2>{identities_[0], identities_[1]} &&
         identity(binding_fd_) ==
             std::array<std::uint64_t, 2>{identities_[2], identities_[3]} &&
         identity(capability_fd_) ==
             std::array<std::uint64_t, 2>{identities_[4], identities_[5]});
    struct stat socket_state{};
    need(::fstat(capability_fd_, &socket_state) == 0 &&
         S_ISSOCK(socket_state.st_mode));
    require_cloexec(capability_fd_);
    std::array<int, 3> high{-1, -1, -1};
    const std::array<int, 3> targets{
        V3_OWNER_INVOICE_FIXED_FD, V3_OWNER_RUN_BINDING_FIXED_FD,
        V3_OWNER_ACCEPT_CAPABILITY_FIXED_FD};
    std::size_t installed = 0;
    try {
        high[0] = duplicate_high(invoice_fd_);
        high[1] = duplicate_high(binding_fd_);
        high[2] = duplicate_high(capability_fd_);
        close_fd(invoice_fd_);
        close_fd(binding_fd_);
        close_fd(capability_fd_);
        for (std::size_t index = 0; index < high.size(); ++index) {
            need(::dup2(high[index], targets[index]) == targets[index]);
            installed += 1;
        }
        for (auto& fd : high) close_fd(fd);
        require_sealed_file(V3_OWNER_INVOICE_FIXED_FD, 208, 0400, false);
        require_sealed_file(V3_OWNER_RUN_BINDING_FIXED_FD,
                            wire::RUN_BINDING_BYTES, 0400, false);
        need(identity(V3_OWNER_INVOICE_FIXED_FD) ==
                 std::array<std::uint64_t, 2>{identities_[0], identities_[1]} &&
             identity(V3_OWNER_RUN_BINDING_FIXED_FD) ==
                 std::array<std::uint64_t, 2>{identities_[2], identities_[3]} &&
             identity(V3_OWNER_ACCEPT_CAPABILITY_FIXED_FD) ==
                 std::array<std::uint64_t, 2>{identities_[4], identities_[5]});
        clear_cloexec(V3_OWNER_INVOICE_FIXED_FD);
        clear_cloexec(V3_OWNER_RUN_BINDING_FIXED_FD);
        clear_cloexec(V3_OWNER_ACCEPT_CAPABILITY_FIXED_FD);
    } catch (...) {
        for (auto& fd : high) close_fd(fd);
        for (std::size_t index = 0; index < installed; ++index)
            (void)::close(targets[index]);
        throw;
    }
}

ParentOfferResidual::ParentOfferResidual(
        ParentV3Authority* parent, Digest parent_instance,
        Digest source_generation, std::uint64_t index, Invoice208 invoice,
        int capability,
        Digest expected)
    : parent_(parent), parent_instance_identity_(parent_instance),
      source_generation_identity_(source_generation), index_(index),
      invoice_(invoice),
      capability_fd_(capability), capability_identity_(identity(capability)),
      expected_ack_(expected) {
    need(parent_ != nullptr && nonzero(parent_instance_identity_) &&
         nonzero(source_generation_identity_) && capability_fd_ >= 0 &&
         invoice_index(invoice_) == index_ && nonzero(expected_ack_));
    require_cloexec(capability_fd_);
}

ParentOfferResidual::ParentOfferResidual(
        ParentOfferResidual&& other) noexcept
    : parent_(other.parent_),
      parent_instance_identity_(other.parent_instance_identity_),
      source_generation_identity_(other.source_generation_identity_),
      index_(other.index_), invoice_(other.invoice_),
      capability_fd_(other.capability_fd_),
      capability_identity_(other.capability_identity_),
      expected_ack_(other.expected_ack_),
      live_(other.live_.exchange(false)) {
    other.capability_fd_ = -1;
}

ParentOfferResidual::~ParentOfferResidual() { close_fd(capability_fd_); }

OwnerRouteSplit::OwnerRouteSplit(
        OwnerOfferAuthority&& offer, ParentOfferResidual&& residual)
    : offer_(std::move(offer)), residual_(std::move(residual)) {}

OwnerOfferAuthority OwnerRouteSplit::take_owner_offer() {
    need(offer_.has_value());
    OwnerOfferAuthority result(std::move(*offer_));
    offer_.reset();
    return result;
}

ParentOfferResidual OwnerRouteSplit::take_parent_residual() {
    need(residual_.has_value());
    ParentOfferResidual result(std::move(*residual_));
    residual_.reset();
    return result;
}

AcceptedInvoiceAuthority::AcceptedInvoiceAuthority(
        ParentV3Authority* parent, Digest parent_instance,
        Digest source_generation, std::uint64_t index, Invoice208 invoice)
    : parent_(parent), parent_instance_identity_(parent_instance),
      source_generation_identity_(source_generation), index_(index),
      invoice_(invoice) {
    need(parent_ != nullptr && nonzero(parent_instance_identity_) &&
         nonzero(source_generation_identity_) &&
         invoice_index(invoice_) == index_);
}

AcceptedInvoiceAuthority::AcceptedInvoiceAuthority(
        AcceptedInvoiceAuthority&& other) noexcept
    : parent_(other.parent_),
      parent_instance_identity_(other.parent_instance_identity_),
      source_generation_identity_(other.source_generation_identity_),
      index_(other.index_), invoice_(other.invoice_),
      live_(other.live_.exchange(false)) {}

ParentV3Authority::ParentV3Authority(
        std::unique_ptr<detail::ParentCore> core,
        Digest accepted_history_identity)
    : core_(std::move(core)),
      accepted_history_identity_(accepted_history_identity) {
    need(core_ != nullptr && nonzero(core_->binding_id));
    binding_identity_ = core_->binding_id;
    need(RAND_bytes(instance_identity_.data(), instance_identity_.size()) ==
             1 &&
         nonzero(instance_identity_));
}

ParentV3Authority::~ParentV3Authority() = default;

AllocatedInvoiceAuthority ParentV3Authority::allocate(
        InvoiceMaterialAuthority&& material, FailureOnlyHook hook) {
    need(material.live_.exchange(false) &&
         equal(material.binding_identity_, binding_identity_) &&
         equal(material.accepted_history_identity_,
               accepted_history_identity_) &&
         equal(material.parent_instance_identity_, instance_identity_) &&
         nonzero(material.source_generation_identity_));
    const auto invoice = material.invoice_;
    const auto index = invoice_index(invoice);
    need(!core_->states.contains(index));
    core_->append(LifecycleState::Allocated, index, invoice, std::move(hook));
    return AllocatedInvoiceAuthority(
        this, instance_identity_, material.source_generation_identity_,
        index, invoice);
}

OwnerRouteSplit ParentV3Authority::export_to_owner(
        AllocatedInvoiceAuthority&& allocated, FailureOnlyHook hook) {
    need(allocated.live_.exchange(false) && allocated.parent_ == this &&
         equal(allocated.parent_instance_identity_, instance_identity_) &&
         nonzero(allocated.source_generation_identity_) &&
         core_->states.at(allocated.index_) == LifecycleState::Allocated &&
         core_->invoices.at(allocated.index_) == allocated.invoice_);
    const auto binding_bytes = wire::canonical_run_binding_bytes(core_->binding);
    int invoice_fd = -1, binding_fd = -1;
    int sockets[2]{-1, -1};
    try {
        invoice_fd = sealed_memfd("kpb-v3-invoice208", allocated.invoice_);
        binding_fd = sealed_memfd("kpb-v3-run-binding", binding_bytes);
        need(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC,
                          0, sockets) == 0);
        Digest challenge{};
        need(RAND_bytes(challenge.data(), challenge.size()) == 1 &&
             nonzero(challenge));
        send_exact(sockets[0], challenge);
        const auto expected = ack_digest(
            challenge, binding_bytes, allocated.invoice_);
        core_->append(LifecycleState::Exported, allocated.index_,
                      allocated.invoice_, std::move(hook));
        OwnerOfferAuthority offer(invoice_fd, binding_fd, sockets[1]);
        invoice_fd = binding_fd = sockets[1] = -1;
        ParentOfferResidual residual(
            this, instance_identity_,
            allocated.source_generation_identity_, allocated.index_,
            allocated.invoice_, sockets[0], expected);
        sockets[0] = -1;
        return OwnerRouteSplit(std::move(offer), std::move(residual));
    } catch (...) {
        close_fd(invoice_fd);
        close_fd(binding_fd);
        close_fd(sockets[0]);
        close_fd(sockets[1]);
        throw;
    }
}

AcceptedInvoiceAuthority ParentV3Authority::accept_from_owner(
        ParentOfferResidual&& residual, FailureOnlyHook hook) {
    struct stat capability_state{};
    need(residual.live_.exchange(false) && residual.parent_ == this &&
         equal(residual.parent_instance_identity_, instance_identity_) &&
         nonzero(residual.source_generation_identity_) &&
         residual.capability_fd_ >= 0 &&
         ::fstat(residual.capability_fd_, &capability_state) == 0 &&
         S_ISSOCK(capability_state.st_mode) &&
         identity(residual.capability_fd_) == residual.capability_identity_ &&
         core_->states.at(residual.index_) == LifecycleState::Exported &&
         core_->invoices.at(residual.index_) == residual.invoice_);
    require_cloexec(residual.capability_fd_);
    try {
        const auto received = receive_packet(
            residual.capability_fd_, residual.expected_ack_.size(), 30000);
        Digest value{};
        std::copy(received.begin(), received.end(), value.begin());
        need(equal(value, residual.expected_ack_));
        close_fd(residual.capability_fd_);
        core_->append(LifecycleState::Accepted, residual.index_,
                      residual.invoice_, std::move(hook));
        return AcceptedInvoiceAuthority(
            this, instance_identity_, residual.source_generation_identity_,
            residual.index_, residual.invoice_);
    } catch (...) {
        close_fd(residual.capability_fd_);
        if (!core_->poisoned) {
            try {
                core_->append(LifecycleState::Poisoned, residual.index_,
                              residual.invoice_, {});
            } catch (...) {}
        }
        throw;
    }
}

void ParentV3Authority::consume(
        AcceptedInvoiceAuthority&& accepted, FailureOnlyHook hook) {
    need(accepted.live_.exchange(false) && accepted.parent_ == this &&
         equal(accepted.parent_instance_identity_, instance_identity_) &&
         nonzero(accepted.source_generation_identity_) &&
         core_->states.at(accepted.index_) == LifecycleState::Accepted &&
         core_->invoices.at(accepted.index_) == accepted.invoice_);
    core_->append(LifecycleState::Consumed, accepted.index_,
                  accepted.invoice_, std::move(hook));
}

void ParentV3Authority::poison(
        AllocatedInvoiceAuthority&& value, FailureOnlyHook hook) {
    need(value.live_.exchange(false) && value.parent_ == this &&
         equal(value.parent_instance_identity_, instance_identity_) &&
         nonzero(value.source_generation_identity_) &&
         core_->states.at(value.index_) == LifecycleState::Allocated);
    core_->append(LifecycleState::Poisoned, value.index_, value.invoice_,
                  std::move(hook));
}

void ParentV3Authority::poison(
        ParentOfferResidual&& value, FailureOnlyHook hook) {
    need(value.live_.exchange(false) && value.parent_ == this &&
         equal(value.parent_instance_identity_, instance_identity_) &&
         nonzero(value.source_generation_identity_) &&
         core_->states.at(value.index_) == LifecycleState::Exported);
    close_fd(value.capability_fd_);
    core_->append(LifecycleState::Poisoned, value.index_, value.invoice_,
                  std::move(hook));
}

void ParentV3Authority::poison(
        AcceptedInvoiceAuthority&& value, FailureOnlyHook hook) {
    need(value.live_.exchange(false) && value.parent_ == this &&
         equal(value.parent_instance_identity_, instance_identity_) &&
         nonzero(value.source_generation_identity_) &&
         core_->states.at(value.index_) == LifecycleState::Accepted);
    core_->append(LifecycleState::Poisoned, value.index_, value.invoice_,
                  std::move(hook));
}

#ifdef KPB_V3_NATIVE_AUTHORITY_TEST_SETUP
std::pair<std::uint64_t, Digest> ParentV3Authority::test_only_latest() const {
    need(!core_->poisoned);
    return {core_->sequence, core_->head};
}

LifecycleState ParentV3Authority::test_only_state(std::uint64_t index) const {
    return core_->states.at(index);
}
#endif

std::unique_ptr<ParentV3Authority> V3NativeAuthorityBridge::open_legacy(
        ParentLedgerDescriptorsAuthority&& descriptors,
        LatestHeadAuthority&& latest,
        const measurement::RunBinding& binding) {
    need(descriptors.live_.exchange(false) && latest.live_.exchange(false));
    auto core = std::make_unique<detail::ParentCore>();
    core->binding = binding;
    core->binding_id = binding_identity(binding);
    core->directory_fd = descriptors.directory_fd_;
    core->journal_fd = descriptors.journal_fd_;
    core->heads_fd = descriptors.heads_fd_;
    core->key_fd = descriptors.mac_key_fd_;
    descriptors.directory_fd_ = descriptors.journal_fd_ =
        descriptors.heads_fd_ = descriptors.mac_key_fd_ = -1;
    core->directory_identity = identity(core->directory_fd);
    core->journal_identity = identity(core->journal_fd);
    core->heads_identity = identity(core->heads_fd);
    need(::flock(core->journal_fd, LOCK_EX | LOCK_NB) == 0);
    core->scan(latest.binding_identity_, latest.sequence_, latest.head_);
    return std::unique_ptr<ParentV3Authority>(
        new ParentV3Authority(std::move(core), Digest{}));
}

std::unique_ptr<ParentV3Authority> V3NativeAuthorityBridge::open_existing(
        ParentLedgerDescriptorsAuthority&& descriptors,
        V3LifecycleControllerAuthority&& controller,
        const measurement::RunBinding& binding) {
    const auto expected = binding_identity(binding);
    need(controller.live_.exchange(false) &&
         equal(controller.binding_identity_, expected) &&
         nonzero(controller.accepted_history_identity_) &&
         controller.updater_.core_ != nullptr);
    const auto accepted_history_identity =
        controller.accepted_history_identity_;
    return open_external(std::move(descriptors),
                         std::move(controller.updater_), binding,
                         accepted_history_identity);
}

std::unique_ptr<ParentV3Authority> V3NativeAuthorityBridge::open_external(
        ParentLedgerDescriptorsAuthority&& descriptors,
        ExternalLatestHeadUpdaterAuthority&& updater,
        const measurement::RunBinding& binding,
        Digest accepted_history_identity) {
    need(descriptors.live_.exchange(false) && updater.core_ != nullptr);
    auto core = std::make_unique<detail::ParentCore>();
    core->binding = binding;
    core->binding_id = binding_identity(binding);
    core->directory_fd = descriptors.directory_fd_;
    core->journal_fd = descriptors.journal_fd_;
    core->heads_fd = descriptors.heads_fd_;
    core->key_fd = descriptors.mac_key_fd_;
    descriptors.directory_fd_ = descriptors.journal_fd_ =
        descriptors.heads_fd_ = descriptors.mac_key_fd_ = -1;
    core->directory_identity = identity(core->directory_fd);
    core->journal_identity = identity(core->journal_fd);
    core->heads_identity = identity(core->heads_fd);
    need(::flock(core->journal_fd, LOCK_EX | LOCK_NB) == 0 &&
         equal(updater.core_->binding_id, core->binding_id) &&
         updater.core_->directory_identity != core->directory_identity);
    core->external_head = std::move(updater.core_);
    core->scan(core->external_head->binding_id,
               core->external_head->sequence,
               core->external_head->local_head);
    // A restart with a live allocation/export/accept state has lost its
    // one-shot in-memory continuation.  It cannot reconstruct that authority
    // from durable bytes, so recovery fails closed rather than minting one.
    for (const auto& [index, state] : core->states) {
        (void)index;
        need(state == LifecycleState::Consumed ||
             state == LifecycleState::Poisoned);
    }
    return std::unique_ptr<ParentV3Authority>(
        new ParentV3Authority(
            std::move(core), accepted_history_identity));
}

#ifdef KPB_V3_NATIVE_AUTHORITY_TEST_SETUP
std::unique_ptr<ParentV3Authority>
V3NativeAuthorityBridge::test_only_open_existing(
        ParentLedgerDescriptorsAuthority&& descriptors,
        LatestHeadAuthority&& latest,
        const measurement::RunBinding& binding) {
    auto parent = open_legacy(
        std::move(descriptors), std::move(latest), binding);
    auto test_history = binding_identity(binding);
    test_history[0] ^= 0xff;
    need(nonzero(test_history) &&
         !equal(test_history, parent->binding_identity_));
    parent->accepted_history_identity_ = test_history;
    return parent;
}

std::unique_ptr<ParentV3Authority>
V3NativeAuthorityBridge::test_only_open_existing(
        ParentLedgerDescriptorsAuthority&& descriptors,
        ExternalLatestHeadUpdaterAuthority&& updater,
        const measurement::RunBinding& binding) {
    auto parent = open_external(
        std::move(descriptors), std::move(updater), binding, Digest{});
    auto test_history = binding_identity(binding);
    test_history[0] ^= 0xff;
    need(nonzero(test_history) &&
         !equal(test_history, parent->binding_identity_));
    parent->accepted_history_identity_ = test_history;
    return parent;
}
#endif

[[noreturn]] void V3NativeAuthorityBridge::refuse_recovery_without_latest_head(
        ParentLedgerDescriptorsAuthority&& descriptors,
        const measurement::RunBinding& binding) {
    need(descriptors.live_.exchange(false));
    (void)binding_identity(binding);
    throw NativeRefused();
}

void owner_accept_from_fixed_fds() {
    require_sealed_file(V3_OWNER_INVOICE_FIXED_FD, 208, 0400, false);
    require_sealed_file(V3_OWNER_RUN_BINDING_FIXED_FD,
                        wire::RUN_BINDING_BYTES, 0400, false);
    struct stat socket_state{};
    need(::fstat(V3_OWNER_ACCEPT_CAPABILITY_FIXED_FD, &socket_state) == 0 &&
         S_ISSOCK(socket_state.st_mode));
    const auto invoice_bytes = read_all_at(V3_OWNER_INVOICE_FIXED_FD, 0, 208);
    Invoice208 invoice{};
    std::copy(invoice_bytes.begin(), invoice_bytes.end(), invoice.begin());
    (void)invoice_index(invoice);
    const auto binding = read_all_at(
        V3_OWNER_RUN_BINDING_FIXED_FD, 0, wire::RUN_BINDING_BYTES);
    const auto challenge_bytes = receive_packet(
        V3_OWNER_ACCEPT_CAPABILITY_FIXED_FD, 32, 30000);
    Digest challenge{};
    std::copy(challenge_bytes.begin(), challenge_bytes.end(),
              challenge.begin());
    need(nonzero(challenge));
    const auto acknowledgement = ack_digest(challenge, binding, invoice);
    send_exact(V3_OWNER_ACCEPT_CAPABILITY_FIXED_FD, acknowledgement);
}

#ifdef KPB_V3_NATIVE_AUTHORITY_TEST_SETUP
std::pair<ParentLedgerDescriptorsAuthority, LatestHeadAuthority>
V3NativeAuthorityTestSetup::initialize_fresh(
        const char* raw_directory, const measurement::RunBinding& binding,
        Digest key) {
    need(raw_directory != nullptr && raw_directory[0] == '/' && nonzero(key));
    const auto binding_id = binding_identity(binding);
    int directory = -1, journal = -1, heads = -1, key_fd = -1;
    try {
        directory = ::open(raw_directory,
                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        need(directory >= 0);
        struct stat directory_state{};
        need(::fstat(directory, &directory_state) == 0 &&
             S_ISDIR(directory_state.st_mode) &&
             directory_state.st_uid == ::geteuid() &&
             (directory_state.st_mode & 0777) == 0700);
        journal = ::openat(directory, "journal.bin",
                           O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                           0600);
        heads = ::openat(directory, "heads.bin",
                         O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                         0600);
        need(journal >= 0 && heads >= 0);
        Bytes journal_header;
        add(journal_header, JOURNAL_MAGIC);
        add(journal_header, binding_id);
        const auto genesis = sha256(journal_header);
        Bytes head_header;
        add(head_header, HEAD_MAGIC);
        add(head_header, binding_id);
        add(head_header, genesis);
        add(head_header, mac(key, head_header));
        need(journal_header.size() == JOURNAL_HEADER_BYTES &&
             head_header.size() == HEAD_HEADER_BYTES);
        write_all_at(journal, journal_header, 0);
        write_all_at(heads, head_header, 0);
        sync_fd(journal);
        sync_fd(heads);
        sync_fd(directory);
        key_fd = sealed_key_fd(key);
        ParentLedgerDescriptorsAuthority descriptors(
            directory, journal, heads, key_fd);
        directory = journal = heads = key_fd = -1;
        return {std::move(descriptors),
                LatestHeadAuthority(binding_id, 0, genesis)};
    } catch (...) {
        close_fd(directory);
        close_fd(journal);
        close_fd(heads);
        close_fd(key_fd);
        throw;
    }
}

ParentLedgerDescriptorsAuthority
V3NativeAuthorityTestSetup::open_descriptors(
        const char* raw_directory, Digest key) {
    need(raw_directory != nullptr && raw_directory[0] == '/');
    int directory = -1, journal = -1, heads = -1, key_fd = -1;
    try {
        directory = ::open(raw_directory,
                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        need(directory >= 0);
        journal = ::openat(directory, "journal.bin",
                           O_RDWR | O_NOFOLLOW | O_CLOEXEC);
        heads = ::openat(directory, "heads.bin",
                         O_RDWR | O_NOFOLLOW | O_CLOEXEC);
        need(journal >= 0 && heads >= 0);
        key_fd = sealed_key_fd(key);
        ParentLedgerDescriptorsAuthority result(
            directory, journal, heads, key_fd);
        directory = journal = heads = key_fd = -1;
        return result;
    } catch (...) {
        close_fd(directory);
        close_fd(journal);
        close_fd(heads);
        close_fd(key_fd);
        throw;
    }
}

std::pair<ParentLedgerDescriptorsAuthority,
          ExternalLatestHeadUpdaterAuthority>
V3NativeAuthorityTestSetup::initialize_fresh_with_external_head(
        const char* raw_directory, const char* raw_external_directory,
        const measurement::RunBinding& binding, Digest key) {
    need(raw_external_directory != nullptr &&
         raw_external_directory[0] == '/' && nonzero(key));
    auto local = initialize_fresh(raw_directory, binding, key);
    int directory = -1, head = -1, key_fd = -1;
    try {
        directory = ::open(raw_external_directory,
                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        need(directory >= 0 &&
             identity(directory) != identity(local.first.directory_fd_));
        struct stat directory_state{};
        need(::fstat(directory, &directory_state) == 0 &&
             S_ISDIR(directory_state.st_mode) &&
             directory_state.st_uid == ::geteuid() &&
             (directory_state.st_mode & 0777) == 0700);
        head = ::openat(directory, "latest-head.bin",
                        O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                        0600);
        need(head >= 0);
        key_fd = sealed_key_fd(key);
        auto core = std::make_unique<detail::ExternalHeadCore>();
        core->binding_id = binding_identity(binding);
        core->directory_fd = directory;
        core->head_fd = head;
        core->key_fd = key_fd;
        directory = head = key_fd = -1;
        core->directory_identity = identity(core->directory_fd);
        core->head_identity = identity(core->head_fd);
        const auto header = core->header(key);
        write_all_at(core->head_fd, header, 0);
        sync_fd(core->head_fd);
        sync_fd(core->directory_fd);
        need(::flock(core->head_fd, LOCK_EX | LOCK_NB) == 0);
        core->scan();
        // The legacy latest-head object is intentionally discarded here.  An
        // external-authority open can consume only the updater below.
        return {std::move(local.first),
                ExternalLatestHeadUpdaterAuthority(std::move(core))};
    } catch (...) {
        close_fd(directory);
        close_fd(head);
        close_fd(key_fd);
        throw;
    }
}

ExternalLatestHeadUpdaterAuthority
V3NativeAuthorityTestSetup::open_external_latest_head(
        const char* raw_external_directory,
        const measurement::RunBinding& binding, Digest key) {
    need(raw_external_directory != nullptr &&
         raw_external_directory[0] == '/' && nonzero(key));
    int directory = -1, head = -1, key_fd = -1;
    try {
        directory = ::open(raw_external_directory,
                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        head = ::openat(directory, "latest-head.bin",
                        O_RDWR | O_NOFOLLOW | O_CLOEXEC);
        need(directory >= 0 && head >= 0);
        key_fd = sealed_key_fd(key);
        auto core = std::make_unique<detail::ExternalHeadCore>();
        core->binding_id = binding_identity(binding);
        core->directory_fd = directory;
        core->head_fd = head;
        core->key_fd = key_fd;
        directory = head = key_fd = -1;
        core->directory_identity = identity(core->directory_fd);
        core->head_identity = identity(core->head_fd);
        need(::flock(core->head_fd, LOCK_EX | LOCK_NB) == 0);
        core->scan();
        return ExternalLatestHeadUpdaterAuthority(std::move(core));
    } catch (...) {
        close_fd(directory);
        close_fd(head);
        close_fd(key_fd);
        throw;
    }
}
#endif

} // namespace kpb::future_recipient::v3_native
