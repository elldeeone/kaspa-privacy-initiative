#pragma once
// Public storage only. This type is not an assignment-validation capability.
#include "../bn254_values.hpp"
#include <array>
#include <memory>

namespace kpi::mpc::packed {

class FormatError : public std::runtime_error {
    const char* code_;
public:
    explicit FormatError(const char* code) : std::runtime_error(code), code_(code) {}
    const char* code() const noexcept { return code_; }
};

enum class PrefixMode : uint64_t { KnownPublic = 1, SecretDerivedRecipe = 2 };
enum class Query : unsigned { A = 0, B1 = 1, B2 = 2, H = 3, L = 4 };
enum class BaseG1 { Alpha, Beta, Delta };
enum class BaseG2 { Beta, Gamma, Delta };

struct Metadata {
    PrefixMode prefix_mode;
    std::string source_sha256, original_model_sha256, pk_sha256, vk_sha256;
    std::string matrix_fingerprint;
    std::array<std::string, 3> compressed_sha256, raw_sha256;
    uint64_t instances, witnesses, constraints, domain;
    uint64_t pk_bytes, vk_bytes;
    std::array<uint64_t, 3> compressed_bytes, raw_bytes;
    Fr omega, omega_inverse, inv_n, coset_shift;
    // Empty in SecretDerivedRecipe mode. This is never a zero placeholder.
    std::vector<Fr> public_prefix;
    uint64_t derived_output_count = 0;
    std::string prefix_recipe_sha256, prefix_layout_sha256;
};

struct AdmissionStats {
    uint64_t matrix_rows = 0, matrix_terms = 0;
    uint64_t g1_points = 0, g2_points = 0;
    uint64_t mapped_public_bytes = 0, maximum_row_terms = 0;
};

// Pure public transport pins. There is deliberately no PK, VK, prefix, setup
// identity or assignment capability in this descriptor or its statistics.
struct RowsDescriptor {
    uint64_t instances, witnesses, constraints;
    std::array<std::filesystem::path, 3> files;
    std::array<std::string, 3> compressed_sha256, raw_sha256;
    std::array<uint64_t, 3> compressed_bytes, raw_bytes;
    std::string matrix_fingerprint;
};
AdmissionStats inspect_matrix_transport(const RowsDescriptor&);

namespace detail { struct Storage; struct Cursor; }

class RowCursor {
    std::unique_ptr<detail::Cursor> cursor_;
    explicit RowCursor(std::shared_ptr<const detail::Storage>, unsigned);
    friend class PackedModel;
public:
    RowCursor(RowCursor&&) noexcept;
    RowCursor& operator=(RowCursor&&) noexcept;
    ~RowCursor();
    RowCursor(const RowCursor&) = delete;
    RowCursor& operator=(const RowCursor&) = delete;
    // Reuses caller storage. Heap use depends on maximum row arity, not rows.
    // The final false return verifies end/checksum/raw digest again.
    bool next(SparseRow& row);
};

class PackedModel {
    std::shared_ptr<const detail::Storage> storage_;
    explicit PackedModel(std::shared_ptr<const detail::Storage>);
public:
    // Copies share the same admitted read-only backing; rvalues copy too.
    PackedModel(const PackedModel&) = default;
    PackedModel& operator=(const PackedModel&) = default;
    // All files are public. Every row and point is admitted before return.
    // The host must additionally give roles immutable/read-only backing files.
    static PackedModel admit(const std::filesystem::path& directory,
        const std::filesystem::path& stock_pk, const std::filesystem::path& stock_vk,
        const std::string& expected_metadata_sha256);
    const Metadata& metadata() const;
    const AdmissionStats& admission_stats() const;
    const std::string& identity() const;
    RowCursor rows(unsigned axis) const;
    G1Value base_g1(BaseG1 role) const;
    G2Value base_g2(BaseG2 role) const;
    G1Value vk_gamma_abc(uint64_t index) const;
    uint64_t query_size(Query query) const;
    G1Value g1_query(Query query, uint64_t index) const;
    G2Value g2_query(uint64_t index) const;
    // Metadata/stat validation before/after a larger operation; this is not a
    // defense against a malicious host that can mutate and restore an inode.
    void check_backing_unchanged() const;
};

}  // namespace kpi::mpc::packed
