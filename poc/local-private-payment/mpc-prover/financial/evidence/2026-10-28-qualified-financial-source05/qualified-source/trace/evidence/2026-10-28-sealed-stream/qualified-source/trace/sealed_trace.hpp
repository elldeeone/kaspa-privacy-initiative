#pragma once

#include <cstddef>
#include <filesystem>
#include <istream>
#include <memory>
#include <string>

namespace kpi::mpc {

// Public program storage only. Each pass reads the SAME kernel-sealed encoded
// bytes. Gzip is a transport; identity and grammar cover canonical plaintext.
class SealedTraceArtifact {
    struct Impl;
    std::unique_ptr<Impl> impl_;
    explicit SealedTraceArtifact(std::unique_ptr<Impl>);
public:
    ~SealedTraceArtifact();
    SealedTraceArtifact(const SealedTraceArtifact&) = delete;
    SealedTraceArtifact& operator=(const SealedTraceArtifact&) = delete;
    static std::shared_ptr<const SealedTraceArtifact> load(const std::filesystem::path&);
    std::unique_ptr<std::istream> stream() const;
    size_t container_bytes() const;
    size_t canonical_bytes() const;
    const std::string& container_sha256() const;
    const std::string& canonical_sha256() const;
    const std::string& decoder_identity() const;
    bool gzip() const;
};

}  // namespace kpi::mpc
