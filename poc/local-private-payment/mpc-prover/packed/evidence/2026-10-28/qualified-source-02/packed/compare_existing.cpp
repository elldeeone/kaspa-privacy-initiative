// Public storage equivalence control. Never constructs an MPC context.
#include "packed_model.hpp"
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <sys/resource.h>

namespace {
using namespace kpi::mpc;
using namespace kpi::mpc::packed;

std::string file_hash(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw FormatError("compare-public-source-open");
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> hash(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!hash || EVP_DigestInit_ex(hash.get(), EVP_sha256(), nullptr) != 1)
        throw FormatError("compare-hash-initialization");
    std::array<char, 65536> block{};
    while (input) {
        input.read(block.data(), block.size());
        if (EVP_DigestUpdate(hash.get(), block.data(), static_cast<size_t>(input.gcount())) != 1)
            throw FormatError("compare-hash-update");
    }
    if (!input.eof()) throw FormatError("compare-public-source-read");
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{}; unsigned length = 0;
    if (EVP_DigestFinal_ex(hash.get(), digest.data(), &length) != 1 || length != 32)
        throw FormatError("compare-hash-finalization");
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    for (unsigned i = 0; i < length; ++i) { out.push_back(digits[digest[i] >> 4]); out.push_back(digits[digest[i] & 15]); }
    return out;
}

struct Text {
    std::ifstream input;
    explicit Text(const std::filesystem::path& path) : input(path) {
        if (!input) throw FormatError("compare-public-source-open");
    }
    std::string token() {
        std::string value;
        if (!(input >> value)) throw FormatError("compare-source-truncated");
        return value;
    }
    void tag(const std::string& expected) {
        if (token() != expected) throw FormatError("compare-source-tag");
    }
    uint64_t count() {
        const auto text = token();
        size_t used = 0;
        const auto value = std::stoull(text, &used);
        if (used != text.size() || std::to_string(value) != text) throw FormatError("compare-source-count");
        return value;
    }
    Fr field() { return parse_fr(token()); }
    AffinePoint point(unsigned degree) {
        tag(degree == 1 ? "g1" : "g2");
        const auto flag = count();
        if (flag > 1) throw FormatError("compare-source-infinity");
        AffinePoint out{flag != 0, {}, {}};
        for (unsigned i = 0; i < degree; ++i) {
            const auto value = token(); (void) parse_fq(value); out.x.push_back(value);
        }
        for (unsigned i = 0; i < degree; ++i) {
            const auto value = token(); (void) parse_fq(value); out.y.push_back(value);
        }
        if (out.infinity && (std::any_of(out.x.begin(), out.x.end(), [](const auto& x) { return x != "0"; }) ||
            std::any_of(out.y.begin(), out.y.end(), [](const auto& y) { return y != "0"; })))
            throw FormatError("compare-source-identity");
        return out;
    }
};

bool same(const AffinePoint& a, const AffinePoint& b) {
    return a.infinity == b.infinity && a.x == b.x && a.y == b.y;
}

struct Compared { uint64_t rows = 0, terms = 0, queries = 0, bases = 0; };
Compared compare(const PackedModel& model, const std::filesystem::path& original,
                 const std::filesystem::path& stock_vk) {
    const auto& meta = model.metadata();
    if (meta.prefix_mode != PrefixMode::KnownPublic || file_hash(original) != meta.original_model_sha256)
        throw FormatError("compare-source-model-pin");
    Text reader(original);
    reader.tag("KPI_MASCOT_PUBLIC_MODEL_V1"); reader.tag("field"); reader.tag(FR_MODULUS);
    reader.tag("curve"); reader.tag("BN254"); reader.tag("reduction"); reader.tag("LibSnark");
    reader.tag("source"); reader.tag(meta.source_sha256);
    reader.tag("pk_sha256"); reader.tag(meta.pk_sha256);
    reader.tag("vk_sha256"); reader.tag(meta.vk_sha256);
    for (const auto& [name, expected] : std::array<std::pair<const char*, uint64_t>, 4>{{
        {"num_instance", meta.instances}, {"num_private", meta.witnesses},
        {"num_constraints", meta.constraints}, {"domain", meta.domain}}}) {
        reader.tag(name); if (reader.count() != expected) throw FormatError("compare-source-shape");
    }
    for (const auto& [name, expected] : std::array<std::pair<const char*, Fr>, 4>{{
        {"omega", meta.omega}, {"omega_inverse", meta.omega_inverse},
        {"inv_n", meta.inv_n}, {"coset_shift", meta.coset_shift}}}) {
        reader.tag(name); if (reader.field() != expected) throw FormatError("compare-source-domain");
    }
    reader.tag("public_inputs");
    if (reader.count() != meta.instances) throw FormatError("compare-prefix-arity");
    for (const auto& value : meta.public_prefix)
        if (reader.field() != value) throw FormatError("compare-prefix-value");
    Compared count;
    for (unsigned axis = 0; axis < 3; ++axis) {
        reader.tag(std::string(1, "ABC"[axis]));
        if (reader.count() != meta.constraints) throw FormatError("compare-source-axis-rows");
        auto cursor = model.rows(axis);
        SparseRow row;
        for (uint64_t i = 0; i < meta.constraints; ++i) {
            reader.tag("row");
            const auto terms = reader.count();
            if (!cursor.next(row) || row.size() != terms) throw FormatError("compare-row-arity");
            for (const auto& term : row) {
                const auto index = reader.count(); const auto coefficient = reader.field();
                if (index != term.index || coefficient != term.coefficient) throw FormatError("compare-exact-row-term");
                ++count.terms;
            }
            ++count.rows;
        }
        if (cursor.next(row)) throw FormatError("compare-extra-row");
    }
    const auto g1_base = [&](const char* name, BaseG1 role) {
        reader.tag(name);
        if (!same(reader.point(1), model.base_g1(role).affine())) throw FormatError("compare-G1-base");
        ++count.bases;
    };
    const auto g2_base = [&](const char* name, BaseG2 role) {
        reader.tag(name);
        if (!same(reader.point(2), model.base_g2(role).affine())) throw FormatError("compare-G2-base");
        ++count.bases;
    };
    g1_base("alpha_g1", BaseG1::Alpha); g1_base("beta_g1", BaseG1::Beta);
    g2_base("beta_g2", BaseG2::Beta); g1_base("delta_g1", BaseG1::Delta); g2_base("delta_g2", BaseG2::Delta);
    for (const auto& [name, query] : std::array<std::pair<const char*, Query>, 5>{{
        {"a_query", Query::A}, {"b_g1_query", Query::B1}, {"b_g2_query", Query::B2},
        {"l_query", Query::L}, {"h_query", Query::H}}}) {
        reader.tag(name);
        if (reader.count() != model.query_size(query)) throw FormatError("compare-query-count");
        for (uint64_t i = 0; i < model.query_size(query); ++i) {
            const auto original_point = reader.point(query == Query::B2 ? 2 : 1);
            const auto actual = query == Query::B2 ? model.g2_query(i).affine() : model.g1_query(query, i).affine();
            if (!same(original_point, actual)) throw FormatError("compare-query-point");
            ++count.queries;
        }
    }
    reader.tag("vk_hex");
    const auto encoded_vk = reader.token();
    std::ifstream vk(stock_vk, std::ios::binary);
    static constexpr char digits[] = "0123456789abcdef";
    std::string actual_vk;
    char byte;
    while (vk.get(byte)) { const auto b = static_cast<unsigned char>(byte); actual_vk.push_back(digits[b >> 4]); actual_vk.push_back(digits[b & 15]); }
    if (!vk.eof() || actual_vk != encoded_vk) throw FormatError("compare-VK-bytes");
    reader.tag("END");
    std::string trailing;
    if (reader.input >> trailing) throw FormatError("compare-source-trailing");
    model.check_backing_unchanged();
    return count;
}
}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc != 5 && argc != 6) throw FormatError("packed-control-arguments");
        const auto model = PackedModel::admit(argv[1], argv[2], argv[3], argv[4]);
        const auto compared = argc == 6 ? compare(model, argv[5], argv[3]) : Compared{};
        struct rusage usage{};
        if (getrusage(RUSAGE_SELF, &usage) != 0) throw FormatError("packed-control-resource-metadata");
        const auto& stat = model.admission_stats();
        const auto& meta = model.metadata();
        std::cout << "{\"schema\":\"kpi-packed-public-admission/v1\",\"status\":\"PASS\",\"admitted\":true,\"full_original_equivalence\":"
            << (argc == 6 ? "true" : "false") << ",\"packed_model_sha256\":\""
            << model.identity() << "\",\"matrix_fingerprint\":\"" << meta.matrix_fingerprint
            << "\",\"prefix_mode\":" << static_cast<uint64_t>(meta.prefix_mode)
            << ",\"known_prefix_values\":" << meta.public_prefix.size()
            << ",\"derived_output_count\":" << meta.derived_output_count
            << ",\"admitted_rows\":" << stat.matrix_rows << ",\"admitted_terms\":" << stat.matrix_terms
            << ",\"admitted_G1\":" << stat.g1_points << ",\"admitted_G2\":" << stat.g2_points
            << ",\"mapped_public_bytes\":" << stat.mapped_public_bytes
            << ",\"maximum_row_terms\":" << stat.maximum_row_terms
            << ",\"max_rss_KiB\":" << usage.ru_maxrss
            << ",\"legacy_model_compared\":" << (argc == 6 ? "true" : "false")
            << ",\"compared_rows\":" << compared.rows << ",\"compared_terms\":" << compared.terms
            << ",\"compared_queries\":" << compared.queries << ",\"compared_bases\":" << compared.bases
            << ",\"private_input_MPC_or_setup_executed\":false}\n";
        return 0;
    } catch (const FormatError& error) {
        std::cout << "{\"schema\":\"kpi-packed-public-admission/v1\",\"status\":\"REJECT\",\"admitted\":false,\"reason\":\""
            << error.code() << "\",\"private_input_MPC_or_setup_executed\":false}\n";
    } catch (...) {
        std::cout << "{\"schema\":\"kpi-packed-public-admission/v1\",\"status\":\"REJECT\",\"admitted\":false,"
            "\"reason\":\"public-codec-or-resource-refusal\",\"private_input_MPC_or_setup_executed\":false}\n";
    }
    return 1;
}
