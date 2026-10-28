#include "public_model.hpp"
#include <algorithm>
#include <fstream>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace kpi::mpc {
namespace {
constexpr const char* FQ_MODULUS =
    "21888242871839275222246405745257275088696311157297823662689037894645226208583";

struct Reader {
    std::istringstream input;
    explicit Reader(const std::string& bytes) : input(bytes) {}
    std::string token() {
        std::string value;
        if (!(input >> value))
            throw std::runtime_error("truncated-public-model");
        return value;
    }
    void tag(const std::string& expected) {
        if (token() != expected)
            throw std::runtime_error("public-model-field-order-or-type");
    }
    size_t count() {
        const auto text = token();
        if (text.empty() || (text.size() > 1 && text[0] == '0') ||
            !std::all_of(text.begin(), text.end(), [](unsigned char c) {
                return c >= '0' && c <= '9';
            }))
            throw std::runtime_error("noncanonical-model-count");
        size_t consumed;
        const auto value = std::stoull(text, &consumed);
        if (consumed != text.size() || value > std::numeric_limits<size_t>::max())
            throw std::runtime_error("model-count-overflow");
        return static_cast<size_t>(value);
    }
    Fr scalar() { return parse_fr(token()); }
    std::string hash() {
        const auto value = token();
        if (value.size() != 64 || value.find_first_not_of("0123456789abcdef") != std::string::npos)
            throw std::runtime_error("model-identity-format");
        return value;
    }
    std::string coordinate() {
        auto value = token();
        if (value.empty() || value.size() > 77 ||
            (value.size() > 1 && value[0] == '0') ||
            value.find_first_not_of("0123456789") != std::string::npos ||
            bigint(value) >= bigint(std::string(FQ_MODULUS)))
            throw std::runtime_error("noncanonical-Fq-coordinate");
        return value;
    }
    AffinePoint point(size_t degree) {
        tag(degree == 1 ? "g1" : "g2");
        const auto infinity = count();
        if (infinity > 1)
            throw std::runtime_error("noncanonical-infinity-flag");
        AffinePoint point{infinity == 1, {}, {}};
        for (size_t i = 0; i < degree; ++i)
            point.x.push_back(coordinate());
        for (size_t i = 0; i < degree; ++i)
            point.y.push_back(coordinate());
        if (point.infinity &&
            (std::any_of(point.x.begin(), point.x.end(), [](const auto& c) { return c != "0"; }) ||
             std::any_of(point.y.begin(), point.y.end(), [](const auto& c) { return c != "0"; })))
            throw std::runtime_error("noncanonical-infinity-coordinates");
        return point;
    }
    std::vector<AffinePoint> query(const std::string& name, size_t degree) {
        tag(name);
        const auto n = count();
        std::vector<AffinePoint> result;
        for (size_t i = 0; i < n; ++i)
            result.push_back(point(degree));
        return result;
    }
    std::vector<SparseRow> matrix(const std::string& name) {
        tag(name);
        const auto rows = count();
        std::vector<SparseRow> result;
        for (size_t row = 0; row < rows; ++row) {
            tag("row");
            const auto terms = count();
            SparseRow current;
            for (size_t i = 0; i < terms; ++i) {
                auto index = count();
                current.push_back({index, scalar()});
            }
            result.push_back(std::move(current));
        }
        return result;
    }
};
}  // namespace

void validate_public_model(const PublicModel& model) {
    const auto n = model.domain.n;
    if (model.num_instance == 0 || model.num_private >
        std::numeric_limits<size_t>::max() - model.num_instance)
        throw std::runtime_error("invalid-variable-counts");
    const auto variables = model.num_instance + model.num_private;
    if (model.num_constraints > std::numeric_limits<size_t>::max() - model.num_instance ||
        n == 0 || n > (size_t{1} << 28) || (n & (n - 1)) != 0 ||
        model.num_constraints + model.num_instance > n)
        throw std::runtime_error("invalid-BN254-Fr-radix2-domain");
    if (model.public_inputs.size() != model.num_instance ||
        model.public_inputs[0] != Fr(1) ||
        model.A.size() != model.num_constraints ||
        model.B.size() != model.num_constraints ||
        model.C.size() != model.num_constraints)
        throw std::runtime_error("incomplete-public-prefix-or-R1CS");
    for (const auto* matrix : {&model.A, &model.B, &model.C})
        for (const auto& row : *matrix)
            for (const auto& term : row)
                if (term.index >= variables)
                    throw std::runtime_error("R1CS-column-out-of-range");
    if (model.a_query.size() != variables || model.b_g1_query.size() != variables ||
        model.b_g2_query.size() != variables || model.l_query.size() != model.num_private ||
        model.h_query.size() != n - 1)
        throw std::runtime_error("Groth16-query-arity");
    if (pow_public(model.domain.omega, bigint(n)) != Fr(1) ||
        (n > 1 && pow_public(model.domain.omega, bigint(n / 2)) == Fr(1)) ||
        model.domain.omega * model.domain.omega_inverse != Fr(1) ||
        Fr(bigint(n)) * model.domain.inv_n != Fr(1) ||
        model.domain.coset_shift == Fr(0) ||
        pow_public(model.domain.coset_shift, bigint(n)) == Fr(1))
        throw std::runtime_error("wrong-domain-root-normalization-or-coset");
}

PublicModel load_public_model(const std::filesystem::path& path) {
    initialize_bn254_field();
    std::ifstream file(path, std::ios::binary);
    if (!file)
        throw std::runtime_error("public-model-unavailable");
    std::string body((std::istreambuf_iterator<char>(file)), {});
    Reader reader(body);
    reader.tag("KPI_MASCOT_PUBLIC_MODEL_V1");
    reader.tag("field");
    reader.tag(FR_MODULUS);
    reader.tag("curve"); reader.tag("BN254");
    reader.tag("reduction"); reader.tag("LibSnark");
    PublicModel model{};
    reader.tag("source"); model.source_identity = reader.hash();
    reader.tag("pk_sha256"); model.proving_key_identity = reader.hash();
    reader.tag("vk_sha256"); model.verifying_key_identity = reader.hash();
    reader.tag("num_instance"); model.num_instance = reader.count();
    reader.tag("num_private"); model.num_private = reader.count();
    reader.tag("num_constraints"); model.num_constraints = reader.count();
    reader.tag("domain"); model.domain.n = reader.count();
    reader.tag("omega"); model.domain.omega = reader.scalar();
    reader.tag("omega_inverse"); model.domain.omega_inverse = reader.scalar();
    reader.tag("inv_n"); model.domain.inv_n = reader.scalar();
    reader.tag("coset_shift"); model.domain.coset_shift = reader.scalar();
    reader.tag("public_inputs");
    const auto instances = reader.count();
    for (size_t i = 0; i < instances; ++i)
        model.public_inputs.push_back(reader.scalar());
    model.A = reader.matrix("A"); model.B = reader.matrix("B"); model.C = reader.matrix("C");
    reader.tag("alpha_g1"); model.alpha_g1 = reader.point(1);
    reader.tag("beta_g1"); model.beta_g1 = reader.point(1);
    reader.tag("beta_g2"); model.beta_g2 = reader.point(2);
    reader.tag("delta_g1"); model.delta_g1 = reader.point(1);
    reader.tag("delta_g2"); model.delta_g2 = reader.point(2);
    model.a_query = reader.query("a_query", 1);
    model.b_g1_query = reader.query("b_g1_query", 1);
    model.b_g2_query = reader.query("b_g2_query", 2);
    model.l_query = reader.query("l_query", 1);
    model.h_query = reader.query("h_query", 1);
    reader.tag("vk_hex");
    model.verifying_key_hex = reader.token();
    if (model.verifying_key_hex.empty() || model.verifying_key_hex.size() % 2 != 0 ||
        model.verifying_key_hex.find_first_not_of("0123456789abcdef") != std::string::npos)
        throw std::runtime_error("invalid-canonical-VK-bytes");
    std::vector<unsigned char> vk_bytes;
    for (size_t i = 0; i < model.verifying_key_hex.size(); i += 2)
        vk_bytes.push_back(static_cast<unsigned char>(
            std::stoul(model.verifying_key_hex.substr(i, 2), nullptr, 16)));
    if (sha256_hex(vk_bytes) != model.verifying_key_identity)
        throw std::runtime_error("verifying-key-content-identity-mismatch");
    reader.tag("END");
    std::string trailing;
    if (reader.input >> trailing)
        throw std::runtime_error("trailing-public-model-data");
    model.encoded_model.assign(body.begin(), body.end());
    model.model_identity = sha256_hex(model.encoded_model);
    validate_public_model(model);
    return model;
}
}  // namespace kpi::mpc
