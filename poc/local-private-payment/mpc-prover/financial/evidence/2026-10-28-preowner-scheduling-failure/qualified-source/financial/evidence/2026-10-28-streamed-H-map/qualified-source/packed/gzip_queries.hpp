#pragma once
// Immutable streaming public query storage; not an assignment capability.
// Exact stock ark-groth16 0.6 ProvingKey<Bn254> compressed bytes, transported
// through one pinned gzip member. No new setup or query mathematics.
#include "packed_model.hpp"
#include "../trace/sealed_trace.hpp"

namespace kpi::mpc::packed {

struct StockQueryShape {
    uint64_t instances;
    uint64_t witnesses;
    uint64_t domain;
};

struct GzipQueryPins {
    std::string container_sha256;
    std::string canonical_pk_sha256;
    std::string decoder_identity;
    std::string vk_sha256;
    uint64_t container_bytes;
    uint64_t canonical_pk_bytes;
};

namespace detail { struct GzipQueries; struct GzipCursor; }

// One sequential proof pass. Queries must be consumed in the stock order
// A -> B1 -> B2 -> H -> L. The cursor must finish before any masked proof
// group opening. A wrong kind/count/frame makes the cursor unusable.
class GzipQueryCursor {
    std::unique_ptr<detail::GzipCursor> cursor_;
    explicit GzipQueryCursor(std::shared_ptr<const detail::GzipQueries>);
    friend class GzipQueryStore;
public:
    GzipQueryCursor(GzipQueryCursor&&) noexcept;
    GzipQueryCursor& operator=(GzipQueryCursor&&) noexcept;
    ~GzipQueryCursor();
    GzipQueryCursor(const GzipQueryCursor&) = delete;
    GzipQueryCursor& operator=(const GzipQueryCursor&) = delete;
    G1Value next_g1(Query expected);
    G2Value next_g2();
    // Verifies every vector was consumed, then canonical EOF/CRC. There is no
    // caller-provided success Boolean or flag that skips this requirement.
    void finish();
};

class GzipQueryStore {
    std::shared_ptr<const detail::GzipQueries> queries_;
    explicit GzipQueryStore(std::shared_ptr<const detail::GzipQueries>);
public:
    // Rvalues also copy this small shared handle; there is no invalid moved
    // store that could bypass the factory's complete-admission invariant.
    GzipQueryStore(const GzipQueryStore&) = default;
    GzipQueryStore& operator=(const GzipQueryStore&) = default;
    // Full point admission precedes return. Artifact canonical/container hashes
    // and sizes, decoder identity, VK prefix and every vector shape must match.
    // The small VK byte span is deep-copied; no caller alias is retained.
    static GzipQueryStore admit(std::shared_ptr<const SealedTraceArtifact>,
        std::span<const unsigned char> canonical_vk,
        const StockQueryShape&, const GzipQueryPins&);
    const StockQueryShape& shape() const;
    const GzipQueryPins& pins() const;
    // A new transport identity, not an assertion of a complete model identity.
    const std::string& transport_identity() const;
    uint64_t query_size(Query) const;
    G1Value base_g1(BaseG1) const;
    G2Value base_g2(BaseG2) const;
    GzipQueryCursor cursor() const;
};

}  // namespace kpi::mpc::packed
