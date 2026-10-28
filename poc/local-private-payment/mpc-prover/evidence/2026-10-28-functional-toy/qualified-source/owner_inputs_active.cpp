#include "owner_inputs_active.hpp"
#include "ExternalIO/Client.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <limits>
#include <memory>
#include <fstream>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdexcept>

namespace kpi::mpc {
namespace {
void require_hash(const std::string& value) {
    if (value.size() != 64 || value.find_first_not_of("0123456789abcdef") != std::string::npos)
        throw std::runtime_error("owner-contract-identity-format");
}

std::string public_key_identity(X509* certificate) {
    if (!certificate)
        throw std::runtime_error("TLS-public-key-certificate-missing");
    const int length = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(certificate), nullptr);
    if (length <= 0)
        throw std::runtime_error("TLS-public-key-encoding");
    std::vector<unsigned char> encoded(static_cast<size_t>(length));
    unsigned char* cursor = encoded.data();
    if (i2d_X509_PUBKEY(X509_get_X509_PUBKEY(certificate), &cursor) != length)
        throw std::runtime_error("TLS-public-key-encoding");
    return sha256_hex(encoded);
}

std::string require_authenticated_peer(client_socket* socket,
                                       const std::string& expected_name,
                                       const std::string& expected_fingerprint) {
    // Upstream verify_peer checks a supplied certificate, but its server path
    // does not require one to be present. Enforce presence, chain, expected
    // identity and pinned certificate BEFORE acknowledging a job or any masks.
    X509* certificate = SSL_get1_peer_certificate(socket->native_handle());
    if (!certificate)
        throw std::runtime_error("owner-TLS-peer-certificate-missing");
    const auto free_certificate = [](X509* value) { X509_free(value); };
    std::unique_ptr<X509, decltype(free_certificate)> owned(certificate, free_certificate);
    if (SSL_get_verify_result(socket->native_handle()) != X509_V_OK ||
        X509_check_host(certificate, expected_name.data(), expected_name.size(),
                        X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS, nullptr) != 1)
        throw std::runtime_error("owner-TLS-chain-or-name");
    unsigned char fingerprint[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    if (X509_digest(certificate, EVP_sha256(), fingerprint, &length) != 1 ||
        length != 32)
        throw std::runtime_error("owner-TLS-certificate-digest");
    static constexpr char digits[] = "0123456789abcdef";
    std::string actual;
    for (unsigned int i = 0; i < length; ++i) {
        actual += digits[fingerprint[i] >> 4];
        actual += digits[fingerprint[i] & 15];
    }
    if (actual.size() != expected_fingerprint.size() ||
        CRYPTO_memcmp(actual.data(), expected_fingerprint.data(), actual.size()) != 0)
        throw std::runtime_error("owner-TLS-certificate-pin");
    return public_key_identity(certificate);
}

void require_frame(const octetStream& frame, size_t count) {
    if (count > std::numeric_limits<size_t>::max() / Fr::size() ||
        frame.get_length() != count * Fr::size())
        throw std::runtime_error("owner-active-field-frame-length");
}

Fr unpack_strict(octetStream& frame) {
    static_assert(std::endian::native == std::endian::little,
                  "Selected MP-SPDZ native Montgomery framing requires little-endian limbs");
    const auto size = static_cast<size_t>(Fr::size());
    if (frame.left() < size)
        throw std::runtime_error("truncated-owner-Fr");
    auto* encoded = frame.consume(size);
    // ExternalIO uses fixed-width Montgomery field representations. Check the
    // raw residue is canonical in that representation before upstream unpack.
    bigint residue;
    mpz_import(residue.get_mpz_t(), size, -1, 1, 0, 0, encoded);
    if (residue >= fr_modulus())
        throw std::runtime_error("owner-Montgomery-Fr-alias");
    octetStream single(size, encoded);
    Fr result;
    result.unpack(single);
    if (!single.done())
        throw std::runtime_error("owner-Fr-frame-not-exhausted");
    return result;
}

std::string frame_bytes(const octetStream& frame) {
    return std::string(reinterpret_cast<const char*>(frame.get_data()), frame.get_length());
}
}  // namespace

std::string canonical_owner_contract(const OwnerInputContract& contract) {
    for (const auto* identity : {&contract.run_nonce, &contract.model_identity,
         &contract.source_identity, &contract.proving_key_identity,
         &contract.verifying_key_identity, &contract.cohort_identity,
         &contract.owner_certificate_sha256})
        require_hash(*identity);
    for (const auto& fingerprint : contract.server_certificate_sha256)
        require_hash(fingerprint);
    const std::set<std::string> server_pins(contract.server_certificate_sha256.begin(),
                                            contract.server_certificate_sha256.end());
    if (server_pins.size() != 3 || server_pins.contains(contract.owner_certificate_sha256))
        throw std::runtime_error("owner-contract-reused-cohort-certificate");
    if (contract.owner_id < 0 || contract.input_count == 0 ||
        contract.input_count > std::numeric_limits<size_t>::max() / (3 * Fr::size()))
        throw std::runtime_error("owner-contract-role-or-shape");
    return std::string("KPI_MASCOT_OWNER_INPUT_V1\nBN254\nFr\n") + FR_MODULUS +
        "\nDDNNT_ACTIVE_3N\n" + contract.run_nonce + "\n" +
        contract.model_identity + "\n" + contract.source_identity + "\n" +
        contract.proving_key_identity + "\n" + contract.verifying_key_identity + "\n" +
        contract.cohort_identity + "\n" + std::to_string(contract.owner_id) + "\n" +
        std::to_string(contract.input_count) + "\nP0\n" + contract.server_certificate_sha256[0] +
        "\nP1\n" + contract.server_certificate_sha256[1] + "\nP2\n" +
        contract.server_certificate_sha256[2] + "\nC" + std::to_string(contract.owner_id) +
        "\n" + contract.owner_certificate_sha256 + "\n";
}

OwnerInputContract load_owner_contract(const std::filesystem::path& path) {
    std::ifstream file(path);
    if (!file)
        throw std::runtime_error("owner-contract-unavailable");
    auto token = [&]() {
        std::string value;
        if (!(file >> value))
            throw std::runtime_error("truncated-owner-contract");
        return value;
    };
    auto tag = [&](const std::string& expected) {
        if (token() != expected)
            throw std::runtime_error("owner-contract-field-order");
    };
    auto count = [&]() {
        const auto value = token();
        if (value.empty() || (value.size() > 1 && value[0] == '0') ||
            value.find_first_not_of("0123456789") != std::string::npos)
            throw std::runtime_error("owner-contract-noncanonical-count");
        return std::stoull(value);
    };
    tag("KPI_OWNER_CONTRACT_V1");
    OwnerInputContract result{};
    tag("run_nonce"); result.run_nonce = token();
    tag("model"); result.model_identity = token();
    tag("source"); result.source_identity = token();
    tag("pk"); result.proving_key_identity = token();
    tag("vk"); result.verifying_key_identity = token();
    tag("cohort"); result.cohort_identity = token();
    tag("owner_id");
    const auto id = count();
    if (id > static_cast<unsigned long long>(std::numeric_limits<int>::max()))
        throw std::runtime_error("owner-id-overflow");
    result.owner_id = static_cast<int>(id);
    tag("input_count");
    const auto n = count();
    if (n > std::numeric_limits<size_t>::max())
        throw std::runtime_error("owner-count-overflow");
    result.input_count = static_cast<size_t>(n);
    for (size_t server = 0; server < 3; ++server) {
        tag("server_certificate_" + std::to_string(server));
        result.server_certificate_sha256[server] = token();
    }
    tag("owner_certificate"); result.owner_certificate_sha256 = token();
    tag("END");
    std::string trailing;
    if (file >> trailing)
        throw std::runtime_error("trailing-owner-contract-data");
    (void) canonical_owner_contract(result);
    return result;
}

ActiveOwnerInputServer::ActiveOwnerInputServer(MascotContext& context, int port_base)
    : context_(context), clients_(context.party_id()), port_base_(port_base) {
    if (port_base < 1024 || port_base > 65533)
        throw std::runtime_error("owner-listen-port-range");
    clients_.start_listening(port_base_);
}

std::vector<AuthScalar> ActiveOwnerInputServer::receive(const OwnerInputContract& contract) {
    const auto canonical = canonical_owner_contract(contract);
    if (!consumed_roles_.insert(contract.owner_id).second)
        throw std::runtime_error("duplicate-owner-job-role");
    context_.agree_public_bytes("owner-contract", std::span(
        reinterpret_cast<const unsigned char*>(canonical.data()), canonical.size()));
    const int owner = clients_.get_client_connection(port_base_);
    if (owner != contract.owner_id)
        throw std::runtime_error("unexpected-external-owner-role");
    auto* socket = clients_.get_socket(owner);
    const auto owner_key = require_authenticated_peer(socket, "C" + std::to_string(owner),
                                                       contract.owner_certificate_sha256);
    if (owner_key == public_key_identity(SSL_get_certificate(socket->native_handle())))
        throw std::runtime_error("owner-and-server-TLS-key-reuse");
    octetStream specification(canonical);
    specification.Send(socket);
    octetStream acknowledgment;
    acknowledgment.Receive(socket);
    const auto expected_ack = sha256_hex(std::span(
        reinterpret_cast<const unsigned char*>(canonical.data()), canonical.size()));
    if (frame_bytes(acknowledgment) != expected_ack)
        throw std::runtime_error("wrong-or-replayed-owner-job-acknowledgment");
    context_.agree_public_bytes("owner-job-ack", std::span(
        acknowledgment.get_data(), acknowledgment.get_length()));

    std::vector<std::array<AuthScalar, 3>> triples(contract.input_count);
    for (auto& triple : triples)
        context_.protocols().preprocessing.get_three(DATA_TRIPLE,
            triple[0], triple[1], triple[2]);
    context_.check_field_pending();
    octetStream mask_components;
    for (const auto& triple : triples)
        for (const auto& component : triple)
            component.get_share().pack(mask_components);  // Never a MAC lane.
    require_frame(mask_components, 3 * contract.input_count);
    mask_components.Send(socket);

    octetStream masked;
    masked.Receive(socket);
    require_frame(masked, contract.input_count);
    context_.agree_public_bytes("owner-masked-input", std::span(masked.get_data(), masked.get_length()));
    std::vector<AuthScalar> inputs;
    for (size_t i = 0; i < contract.input_count; ++i)
        inputs.push_back(context_.public_constant(unpack_strict(masked)) - triples[i][0]);
    if (!masked.done())
        throw std::runtime_error("trailing-owner-masked-input");
    clients_.close_connection(owner);
    return inputs;
}

void send_private_inputs_active(const std::array<std::string, 3>& hostnames,
                                int port_base, const OwnerInputContract& contract,
                                std::span<const Fr> values) {
    if (values.size() != contract.input_count)
        throw std::runtime_error("owner-private-input-count");
    const auto canonical = canonical_owner_contract(contract);
    Client client(std::vector<std::string>(hostnames.begin(), hostnames.end()),
                  port_base, contract.owner_id);
    if (client.sockets.size() != 3 || frame_bytes(client.specification) != canonical)
        throw std::runtime_error("owner-model-cohort-field-or-job-disagreement");
    std::set<std::string> server_keys;
    for (size_t server = 0; server < 3; ++server) {
        const auto server_key = require_authenticated_peer(client.sockets[server],
            "P" + std::to_string(server), contract.server_certificate_sha256[server]);
        if (!server_keys.insert(server_key).second ||
            server_key == public_key_identity(SSL_get_certificate(client.sockets[server]->native_handle())))
            throw std::runtime_error("owner-cohort-TLS-key-reuse");
    }
    const auto ack = sha256_hex(std::span(
        reinterpret_cast<const unsigned char*>(canonical.data()), canonical.size()));
    for (auto* socket : client.sockets)
        octetStream(ack).Send(socket);

    std::vector<std::array<Fr, 3>> triples(values.size());
    for (auto* socket : client.sockets) {
        octetStream frame;
        frame.Receive(socket);
        require_frame(frame, 3 * values.size());  // No one-mask fallback.
        for (auto& triple : triples)
            for (auto& value : triple)
                value += unpack_strict(frame);
        if (!frame.done())
            throw std::runtime_error("trailing-owner-triple-components");
    }
    for (const auto& triple : triples)
        if (triple[0] * triple[1] != triple[2])
            throw std::runtime_error("owner-active-triple-check");
    octetStream masked;
    for (size_t i = 0; i < values.size(); ++i)
        Fr(values[i] + triples[i][0]).pack(masked);
    require_frame(masked, values.size());
    for (auto* socket : client.sockets)
        masked.Send(socket);
}
}  // namespace kpi::mpc
