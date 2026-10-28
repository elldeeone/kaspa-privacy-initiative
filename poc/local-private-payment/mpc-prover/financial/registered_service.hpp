#pragma once

#include "../auth_field.hpp"
#include "../history/epoch_journal.hpp"
#include <filesystem>
#include <memory>

namespace kpi::mpc::financial {

// These are public, immutable selections, not an authority a caller may pass
// into a factory. Only RegisteredService's compiled fixed registry supplies one.
struct FixedPublicProgram {
    std::filesystem::path executable;
    history::Digest executable_sha256;
    std::filesystem::path source_closure;
    history::Digest source_closure_sha256;
    std::filesystem::path specification;
    history::Digest specification_sha256;
    std::filesystem::path work_parent;
    // Empty for a native exporter. Python acquisition launchers use a pinned
    // interpreter and sealed source descriptors, never a reopened shebang.
    std::filesystem::path interpreter;
    history::Digest interpreter_sha256{};
    struct PublicFile { std::filesystem::path path; history::Digest sha256; };
    std::vector<PublicFile> runtime_files;
    struct PublicAlias { std::filesystem::path path, target; };
    std::vector<PublicAlias> runtime_aliases;
    std::filesystem::path namespace_tool;
    history::Digest namespace_tool_sha256{};
};

class RegisteredService {
    struct Storage;
    const std::shared_ptr<const Storage> storage_;
    const MascotContext* const context_;
    const uint64_t generation_, epoch_;
    RegisteredService(MascotContext&, std::shared_ptr<const Storage>);
    RegisteredService(const RegisteredService&) = default;
    friend class RegisteredFinancialSelection;
public:
    RegisteredService(RegisteredService&&) = delete;
    RegisteredService& operator=(const RegisteredService&) = delete;
    RegisteredService& operator=(RegisteredService&&) = delete;
    ~RegisteredService();

    // No job path, registry, epoch, configuration struct or qualification mode
    // is accepted. An unconfigured build refuses before acquiring any head.
    static RegisteredService open_selected(MascotContext&);
    void require_live(MascotContext&) const;
    const history::Digest& identity() const;
    // Stable SPEC label only. The registration must precede and exclude the
    // acquisition/exporter specifications. This label never replaces the
    // full identity() in private authority, peer agreement or job dependencies.
    const history::Digest& registered_identity() const;
    const history::EpochKey& key() const;
    const history::Digest& registration() const;
    unsigned party_id() const;
    const std::filesystem::path& journal_directory() const;
    const std::filesystem::path& anchor_directory() const;
    const FixedPublicProgram& acquisition() const;
    const FixedPublicProgram& exporter() const;
    const history::Digest& model_identity() const;
    const history::Digest& native_parameters_identity() const;
    const history::Digest& native_tail_identity() const;
    const std::filesystem::path& native_tail_path() const;
    std::span<const unsigned char> native_tail() const;
    const std::vector<std::filesystem::path>& private_directories() const;
};

} // namespace kpi::mpc::financial
