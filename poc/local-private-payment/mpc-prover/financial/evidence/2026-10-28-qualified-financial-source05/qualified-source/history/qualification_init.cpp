// Separate, nonfinancial setup executable for one fixed public fixture.
// No epoch_ticket.hpp, owner input, MPC, proof or settlement entry is linked.
#ifndef KPI_HISTORY_UNFUNDED_SETUP
#error "qualification initializer requires the separate unfunded setup build"
#endif
#ifndef KPI_QUALIFICATION_BUILD_SHA256
#error "qualification initializer requires its selected source/tool build identity"
#endif
#include "qualification_descriptor.hpp"
#include <cerrno>
#include <fcntl.h>
#include <iostream>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
using namespace kpi::mpc::history;
namespace q = qualification;
using q::need;

void sync(int fd) {
    int result;
    do { result = ::fsync(fd); } while (result < 0 && errno == EINTR);
    need(result == 0);
}
void sync_directory(const std::filesystem::path& path) {
    const auto fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    need(fd >= 0);
    try { sync(fd); } catch (...) { ::close(fd); throw; }
    need(::close(fd) == 0);
}
std::filesystem::path canonical_parent(const std::filesystem::path& path) {
    need(path.is_absolute() && path == path.lexically_normal());
    need(path.string().find_first_of("\r\n\t") == std::string::npos);
    for (auto current = path.parent_path(); !current.empty(); current = current.parent_path()) {
        need(!std::filesystem::is_symlink(std::filesystem::symlink_status(current)));
        if (current == current.root_path()) break;
    }
    struct stat info{};
    need(::lstat(path.parent_path().c_str(), &info) == 0 && S_ISDIR(info.st_mode)
         && info.st_uid == ::getuid());
    return path;
}
void make_directory(const std::filesystem::path& path) { need(::mkdir(path.c_str(), 0700) == 0); }
void write_new(const std::filesystem::path& path, const std::string& value) {
    const auto fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0400);
    need(fd >= 0);
    try {
        size_t at = 0;
        while (at < value.size()) {
            const auto count = ::write(fd, value.data() + at, value.size() - at);
            if (count < 0 && errno == EINTR) continue;
            need(count > 0); at += static_cast<size_t>(count);
        }
        sync(fd);
    } catch (...) { ::close(fd); throw; }
    need(::close(fd) == 0);
}
Digest executable_identity() {
    const auto fd = ::open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    need(fd >= 0);
    struct stat info{};
    need(::fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && info.st_nlink == 1 && info.st_size > 0);
    q::Bytes bytes(static_cast<size_t>(info.st_size));
    size_t at = 0;
    while (at < bytes.size()) {
        const auto count = ::read(fd, bytes.data() + at, bytes.size() - at);
        if (count < 0 && errno == EINTR) continue;
        need(count > 0); at += static_cast<size_t>(count);
    }
    need(::close(fd) == 0); return digest(bytes);
}
}

int main(int argc, char** argv) {
    try {
        need(argc == 5);
        const auto root = canonical_parent(std::filesystem::path(argv[1]));
        q::Inputs input{{unhex(argv[2]), unhex(argv[3]), unhex(argv[4])}, {},
            unhex(KPI_QUALIFICATION_BUILD_SHA256), executable_identity(), root};
        need(RAND_bytes(input.public_nonce.data(), input.public_nonce.size()) == 1);
        // Complete fixture/key/derivation admission occurs before any mkdir.
        const auto descriptor = q::describe(input);
        make_directory(root); // Existing or partially failed roots are never reused.
        for (unsigned i = 0; i < 3; ++i) {
            const auto role = root / ("party-" + std::to_string(i));
            make_directory(role); make_directory(role / "journal"); make_directory(role / "anchor");
            auto journal = EpochJournal::initialize_fresh_unfunded(role / "journal", role / "anchor",
                descriptor.key, descriptor.registration_digest);
            const auto state = journal.snapshot();
            need(state.phase == Phase::Ready && state.sequence == 0 && state.seen_nullifiers.empty()
                 && state.checkpoint == descriptor.initial_checkpoint);
            sync_directory(role);
        }
        write_new(descriptor.registration_file, descriptor.registration_file_bytes);
        std::string role_specs = "[";
        for (unsigned i = 0; i < 3; ++i) {
            const auto& path = descriptor.role_spec_files[i];
            const auto& body = descriptor.role_specs[i];
            write_new(path, body); sync_directory(path.parent_path());
            if (i) role_specs += ',';
            role_specs += q::object({{"party_id", std::to_string(i)}, {"path", q::quote(path.string())},
                                    {"sha256", q::quote(hex(digest(q::raw(body))))}});
        }
        role_specs += ']';
        sync_directory(root); sync_directory(root.parent_path());
        std::cout << q::object({{"schema", q::quote("kpb-unregistered-qualification-bootstrap-result/v2")},
            {"scope", q::quote(q::SCOPE)}, {"registration_file", q::quote(descriptor.registration_file.string())},
            {"registration_file_sha256", q::quote(hex(descriptor.registration_file_sha256))},
            {"registration_sha256", q::quote(hex(descriptor.registration_digest))},
            {"initial_checkpoint_hex32", q::quote(hex(descriptor.initial_checkpoint))},
            {"qualification_epoch_hex32", q::quote(hex(descriptor.key.epoch))},
            {"role_specs", role_specs}, {"parties", "3"}, {"registered_financial_service", "false"}}) << '\n';
    } catch (...) {
        std::cerr << "qualification bootstrap refused\n";
        return 1;
    }
}
