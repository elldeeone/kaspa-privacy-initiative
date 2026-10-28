#include "registered_service.hpp"
#include "registered_service_config.hpp"
#include "registered_service_selection.hpp"
#if KPI_REGISTERED_FINANCIAL_CONFIGURED == 1
#ifndef KPI_REGISTERED_ROSTER_TRANSPORT_HEADER
#error "Registered financial entry requires the selected actual DER-pinned transport header"
#endif
#include KPI_REGISTERED_ROSTER_TRANSPORT_HEADER
#endif
#include <algorithm>
#include <fcntl.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <set>
#include <sys/stat.h>
#include <unistd.h>

namespace kpi::mpc::financial {
namespace {
using Bytes = std::vector<unsigned char>;
using Config = registered_detail::Configuration;
[[noreturn]] void refuse() { throw history::Refused(); }
void need(bool value) { if (!value) refuse(); }
class Fd {
public:
    int value;
    explicit Fd(int fd) : value(fd) { need(fd >= 0); }
    ~Fd() { close(value); }
    Fd(const Fd&) = delete;
};
class Exclusions {
    std::vector<std::filesystem::path> roots_;
    std::set<std::pair<dev_t, ino_t>> inodes_;
    static bool inside(const std::filesystem::path& path, const std::filesystem::path& root) {
        auto p = path.begin();
        for (auto r = root.begin(); r != root.end(); ++r, ++p)
            if (p == path.end() || *p != *r) return false;
        return true;
    }
public:
    Exclusions(const Config& config, unsigned party) : roots_(config.private_directories.at(party)) {
        roots_.push_back(config.journals.at(party)); roots_.push_back(config.anchors.at(party));
        need(!roots_.empty());
        for (auto& root : roots_) {
            need(root.is_absolute() && root.lexically_normal() == root);
            struct stat st{}; need(lstat(root.c_str(), &st) == 0 && S_ISDIR(st.st_mode));
            need(std::filesystem::canonical(root) == root);
            inodes_.insert({st.st_dev, st.st_ino});
            // Metadata only, no following symlinks and no private body reads.
            for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
                need(lstat(entry.path().c_str(), &st) == 0);
                inodes_.insert({st.st_dev, st.st_ino});
            }
        }
    }
    void path(const std::filesystem::path& value) const {
        need(value.is_absolute() && value.lexically_normal() == value);
        const auto actual = std::filesystem::weakly_canonical(value);
        for (const auto& root : roots_)
            need(!inside(value, root) && !inside(root, value) && !inside(actual, root) && !inside(root, actual));
    }
    void inode(const struct stat& value) const { need(!inodes_.contains({value.st_dev, value.st_ino})); }
};
Bytes pinned_file(const std::filesystem::path& path, const history::Digest& expected, const Exclusions& excluded) {
    excluded.path(path);
    Fd fd(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    struct stat before{}, after{};
    need(fstat(fd.value, &before) == 0 && S_ISREG(before.st_mode) && before.st_size >= 0);
    excluded.inode(before);
    Bytes bytes(static_cast<size_t>(before.st_size));
    size_t done = 0;
    while (done < bytes.size()) {
        const auto n = pread(fd.value, bytes.data() + done, bytes.size() - done, done);
        need(n > 0); done += static_cast<size_t>(n);
    }
    need(fstat(fd.value, &after) == 0 && before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
         before.st_size == after.st_size && before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
         before.st_mtim.tv_nsec == after.st_mtim.tv_nsec && before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
         before.st_ctim.tv_nsec == after.st_ctim.tv_nsec && history::digest(bytes) == expected);
    return bytes;
}
void fixed_directory(const std::filesystem::path& path) {
    need(path.is_absolute() && path.lexically_normal() == path && std::filesystem::canonical(path) == path);
    struct stat st{};
    need(lstat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == geteuid() &&
         !(st.st_mode & (S_IWGRP | S_IWOTH)));
}
void add(Bytes& out, std::span<const unsigned char> value) { out.insert(out.end(), value.begin(), value.end()); }
void number(Bytes& out, uint64_t n) { for (unsigned i = 0; i < 8; ++i) out.push_back(n >> (8 * i)); }
void path_binding(Bytes& out, const std::filesystem::path& path) {
    const auto s = path.string(); number(out, s.size()); out.insert(out.end(), s.begin(), s.end());
}
void program(Bytes& binding, const FixedPublicProgram& p, const Exclusions& excluded) {
    (void)pinned_file(p.executable, p.executable_sha256, excluded);
    (void)pinned_file(p.source_closure, p.source_closure_sha256, excluded);
    (void)pinned_file(p.specification, p.specification_sha256, excluded);
    excluded.path(p.work_parent); fixed_directory(p.work_parent);
    for (const auto& pth : {p.executable, p.source_closure, p.specification, p.work_parent}) path_binding(binding, pth);
    for (const auto& id : {p.executable_sha256, p.source_closure_sha256, p.specification_sha256}) add(binding, id);
    path_binding(binding, p.interpreter); add(binding, p.interpreter_sha256);
    need(p.interpreter.empty() == (p.interpreter_sha256 == history::Digest{}));
    if (!p.interpreter.empty()) (void)pinned_file(p.interpreter, p.interpreter_sha256, excluded);
    path_binding(binding, p.namespace_tool); add(binding, p.namespace_tool_sha256);
    need(p.namespace_tool.empty() == (p.namespace_tool_sha256 == history::Digest{}));
    if (!p.namespace_tool.empty()) (void)pinned_file(p.namespace_tool, p.namespace_tool_sha256, excluded);
    number(binding, p.runtime_files.size());
    std::set<std::filesystem::path> selected_leaves{p.executable};
    if (!p.interpreter.empty()) selected_leaves.insert(p.interpreter);
    for (const auto& file : p.runtime_files) {
        (void)pinned_file(file.path, file.sha256, excluded); path_binding(binding, file.path); add(binding, file.sha256);
        need(selected_leaves.insert(file.path).second);
    }
    number(binding, p.runtime_aliases.size());
    std::set<std::filesystem::path> aliases;
    for (const auto& alias : p.runtime_aliases) {
        excluded.path(alias.path); excluded.path(alias.target);
        need(alias.path != alias.target && selected_leaves.contains(alias.target) &&
             !selected_leaves.contains(alias.path) && aliases.insert(alias.path).second);
        path_binding(binding, alias.path); path_binding(binding, alias.target);
    }
}
history::Digest authenticate(const Config& c, unsigned party) {
    const Exclusions excluded(c, party);
    need(c.key.epoch == history::unhex("1719a11d82194639da551cd7302ad3ea94e42a0e424962ac40719f5634d38b94") &&
         c.key.chain == history::unhex("f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370") &&
         c.key.pool == history::unhex("d68068e3eecfe9fe1b2fcc63026fe7a5268829efa37f4f64c2e7374798e94adf") &&
         c.key.domain == history::unhex("a0a1b4fbf4ce8505f17b24b354ffa81fc4201dc1e130b0358e3bc849611186e0") &&
         c.key.profile == history::unhex("ea19260a60a8d0a54b8ad9848f82317c1d84059a1881be34d318bcca42493700") &&
         c.key.service == history::unhex("ce821210834e870b6eebe3851b0b003b1b33cf343b1a17a996987f35dda514b5"));
    const std::string tag = "KPB_REGISTERED_FINANCIAL_SERVICE_V1\n";
    Bytes binding(tag.begin(), tag.end()); add(binding, history::encode(c.key)); add(binding, c.registration);
    (void)pinned_file(c.registration_file, c.registration_file_sha256, excluded);
    path_binding(binding, c.registration_file); add(binding, c.registration_file_sha256);
    std::set<history::Digest> public_keys;
    std::set<std::filesystem::path> stores;
    for (size_t role = 0; role < 3; ++role) {
        // Other roles' durable stores must remain outside this role's mount
        // namespace. Their exact configured paths still enter the common ID.
        for (const auto& p : {c.journals[role], c.anchors[role]})
            need(p.is_absolute() && p.lexically_normal() == p && stores.insert(p).second);
        if (role == party) { fixed_directory(c.journals[role]); fixed_directory(c.anchors[role]); }
        need(!c.private_directories[role].empty());
        number(binding, c.private_directories[role].size());
        for (const auto& path : c.private_directories[role]) {
            need(path.is_absolute() && path.lexically_normal() == path); path_binding(binding, path);
        }
        path_binding(binding, c.journals[role]); path_binding(binding, c.anchors[role]);
        const auto pem = pinned_file(c.certificates[role], c.certificate_pem_sha256[role], excluded);
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(pem.data(), pem.size()), BIO_free);
        need(bool(bio));
        std::unique_ptr<X509, decltype(&X509_free)> cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), X509_free);
        need(bool(cert));
        unsigned char* raw = nullptr; const int length = i2d_X509(cert.get(), &raw);
        need(length > 0 && raw); const auto der_sha = history::digest(std::span(raw, length)); OPENSSL_free(raw);
        need(der_sha == c.key.server_certificates[role]);
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(X509_get_pubkey(cert.get()), EVP_PKEY_free);
        need(bool(key)); raw = nullptr; const int key_length = i2d_PUBKEY(key.get(), &raw);
        need(key_length > 0 && raw); const auto spki = history::digest(std::span(raw, key_length)); OPENSSL_free(raw);
        need(public_keys.insert(spki).second);
        path_binding(binding, c.certificates[role]); add(binding, c.certificate_pem_sha256[role]); add(binding, spki);
    }
    program(binding, c.acquisition, excluded); program(binding, c.exporter, excluded);
    (void)pinned_file(c.native_parameters_file, c.native_parameters, excluded);
    (void)pinned_file(c.native_tail_file, c.native_tail, excluded);
    add(binding, c.model); add(binding, c.native_parameters); add(binding, c.native_tail);
    path_binding(binding, c.native_parameters_file); path_binding(binding, c.native_tail_file);
    return history::digest(binding);
}
Config selected_configuration() {
#if KPI_REGISTERED_FINANCIAL_CONFIGURED == 1
    // Defined only by the ROOT-owned selected source header. No runtime input
    // can supply this configuration or select a new epoch/store.
    return registered_detail::selected_configuration();
#else
    refuse();
#endif
}
void authenticated_transport(MascotContext& context, const Config& config) {
#if KPI_REGISTERED_FINANCIAL_CONFIGURED == 1
    const auto* player = dynamic_cast<const RosterPinnedPlayer*>(&context.player());
    need(player && player->authenticated_roster() == config.key.server_certificates);
#else
    (void)context; (void)config; refuse();
#endif
}
} // namespace

struct RegisteredService::Storage {
    const Config config;
    const history::Digest identity;
    const history::Digest registered_identity;
    const unsigned party;
    const Bytes native_tail;
    Storage(Config c, history::Digest i, history::Digest stable, unsigned p, Bytes t)
        : config(std::move(c)), identity(i), registered_identity(stable), party(p), native_tail(std::move(t)) {}
};
RegisteredService::RegisteredService(MascotContext& c, std::shared_ptr<const Storage> s)
    : storage_(std::move(s)), context_(&c), generation_(c.generation()), epoch_(c.failure_epoch()) {}
RegisteredService::~RegisteredService() = default;
RegisteredService RegisteredService::open_selected(MascotContext& c) {
    try {
        c.require_healthy(); need(c.party_id() >= 0 && c.party_id() < 3);
        const unsigned party = static_cast<unsigned>(c.party_id());
        auto config = selected_configuration(); authenticated_transport(c, config);
        const auto identity = authenticate(config, party);
        auto journal = history::EpochJournal::open_existing(config.journals[party], config.anchors[party],
                                                          config.key, config.registration);
        const auto snapshot = journal.snapshot();
        need(snapshot.key == config.key && snapshot.registration == config.registration);
        const Exclusions excluded(config, party);
        auto tail = pinned_file(config.native_tail_file, config.native_tail, excluded);
        const std::string stable_tag = "KPB_REGISTERED_FINANCIAL_SERVICE_ID_V1\n";
        Bytes stable_bytes(stable_tag.begin(), stable_tag.end());
        add(stable_bytes, history::encode(config.key)); add(stable_bytes, config.registration);
        const auto stable = history::digest(stable_bytes);
        c.agree_public_bytes("registered-financial-service", identity);
        return RegisteredService(c, std::make_shared<const Storage>(std::move(config), identity, stable, party, std::move(tail)));
    } catch (...) { c.poison(); refuse(); }
}
void RegisteredService::require_live(MascotContext& c) const {
    try {
        c.require_healthy(); need(context_ == &c && generation_ == c.generation() && epoch_ == c.failure_epoch() &&
                                 storage_->party == static_cast<unsigned>(c.party_id()) &&
                                 authenticate(storage_->config, storage_->party) == storage_->identity);
        authenticated_transport(c, storage_->config);
    } catch (...) { c.poison(); refuse(); }
}
const history::Digest& RegisteredService::identity() const { return storage_->identity; }
const history::Digest& RegisteredService::registered_identity() const { return storage_->registered_identity; }
const history::EpochKey& RegisteredService::key() const { return storage_->config.key; }
const history::Digest& RegisteredService::registration() const { return storage_->config.registration; }
unsigned RegisteredService::party_id() const { return storage_->party; }
const std::filesystem::path& RegisteredService::journal_directory() const { return storage_->config.journals[storage_->party]; }
const std::filesystem::path& RegisteredService::anchor_directory() const { return storage_->config.anchors[storage_->party]; }
const FixedPublicProgram& RegisteredService::acquisition() const { return storage_->config.acquisition; }
const FixedPublicProgram& RegisteredService::exporter() const { return storage_->config.exporter; }
const history::Digest& RegisteredService::model_identity() const { return storage_->config.model; }
const history::Digest& RegisteredService::native_parameters_identity() const { return storage_->config.native_parameters; }
const history::Digest& RegisteredService::native_tail_identity() const { return storage_->config.native_tail; }
const std::filesystem::path& RegisteredService::native_tail_path() const { return storage_->config.native_tail_file; }
std::span<const unsigned char> RegisteredService::native_tail() const { return storage_->native_tail; }
const std::vector<std::filesystem::path>& RegisteredService::private_directories() const {
    return storage_->config.private_directories[storage_->party];
}
} // namespace kpi::mpc::financial
