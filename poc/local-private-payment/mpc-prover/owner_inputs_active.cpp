#include "owner_inputs_active.hpp"
#include "owner_input_ddnnt.hpp"
#include "owner_cohort_ingress.hpp"
#include "p1_capture_seams.hpp"
#include "ExternalIO/Client.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <memory>
#include <fstream>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdexcept>

namespace kpi::mpc {
namespace {
inline constexpr std::size_t OWNER_DDNNT_MULTIPLICATION_BATCH = 4096;

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

std::string frame_bytes(const octetStream& frame) {
    return std::string(reinterpret_cast<const char*>(frame.get_data()), frame.get_length());
}

template<class T>
void wipe_vector(std::vector<T>& values) noexcept {
    if (!values.empty())
        OPENSSL_cleanse(values.data(), values.size() * sizeof(T));
    values.clear();
    std::vector<T>().swap(values);
}

void wipe_frame(octetStream& frame) noexcept {
    if (frame.get_length() != 0)
        OPENSSL_cleanse(frame.get_data(), frame.get_length());
    frame.clear();
}

template<class T>
class VectorWipeGuard {
    std::vector<T>* values_;
public:
    explicit VectorWipeGuard(std::vector<T>& values) : values_(&values) {}
    ~VectorWipeGuard() { if (values_ != nullptr) wipe_vector(*values_); }
    void release() noexcept { values_ = nullptr; }
};

class FrameWipeGuard {
    octetStream* frame_;
public:
    explicit FrameWipeGuard(octetStream& frame) : frame_(&frame) {}
    ~FrameWipeGuard() { if (frame_ != nullptr) wipe_frame(*frame_); }
    void release() noexcept { frame_ = nullptr; }
};

std::vector<AuthScalar> prepare_ddnnt_input_supply(
        MascotContext& context, std::size_t input_count,
        octetStream& preprocessing_frame) {
    if (input_count == 0 ||
        input_count > std::numeric_limits<std::size_t>::max() /
                          DDNNT_COMPONENT_COUNT ||
        input_count * DDNNT_COMPONENT_COUNT >
            std::numeric_limits<std::size_t>::max() /
                static_cast<std::size_t>(Fr::size()))
        throw std::runtime_error("owner-ddnnt-preprocessing-shape");

    FrameWipeGuard preprocessing_guard(preprocessing_frame);
    preprocessing_frame.reserve(input_count * DDNNT_COMPONENT_COUNT *
                                static_cast<std::size_t>(Fr::size()));
    std::vector<AuthScalar> masks;
    VectorWipeGuard<AuthScalar> masks_guard(masks);
    masks.reserve(input_count);
    for (std::size_t first = 0; first < input_count;
         first += OWNER_DDNNT_MULTIPLICATION_BATCH) {
        const auto count = std::min(OWNER_DDNNT_MULTIPLICATION_BATCH,
                                    input_count - first);
        std::vector<AuthScalar> s(count), r(count), w(count);
        VectorWipeGuard<AuthScalar> s_guard(s);
        VectorWipeGuard<AuthScalar> r_guard(r);
        VectorWipeGuard<AuthScalar> w_guard(w);
        for (std::size_t index = 0; index < count; ++index)
            context.protocols().preprocessing.get_three(
                DATA_TRIPLE, s[index], r[index], w[index]);
        auto v = context.random_auth_batch(
            p1_capture::ScalarCaptureSite::OwnerDdnntRandomV, count);
        VectorWipeGuard<AuthScalar> v_guard(v);
        auto u = context.multiply_batch(
            p1_capture::ScalarCaptureSite::OwnerDdnntProductU, v, r);
        VectorWipeGuard<AuthScalar> u_guard(u);
        // No local value share crosses the owner TLS boundary until the stock
        // preprocessing, multiplication, MAC and checked-broadcast state for
        // this complete public chunk has finished.
        context.check_field_pending();
        // The owner receives value shares only. Preserve P1's complete typed
        // authenticated triple share/MAC lane before packing and wiping. This
        // is not a claim to capture internal OT/PRNG coins or other host state.
        context.capture_authenticated_values(
            p1_capture::ScalarCaptureSite::OwnerDdnntTripleS, s);
        context.capture_authenticated_values(
            p1_capture::ScalarCaptureSite::OwnerDdnntTripleR, r);
        context.capture_authenticated_values(
            p1_capture::ScalarCaptureSite::OwnerDdnntTripleW, w);
        for (std::size_t index = 0; index < count; ++index) {
            s[index].get_share().pack(preprocessing_frame);
            r[index].get_share().pack(preprocessing_frame);
            w[index].get_share().pack(preprocessing_frame);
            v[index].get_share().pack(preprocessing_frame);
            u[index].get_share().pack(preprocessing_frame);
            masks.push_back(s[index]);
        }
    }
    require_owner_fr_frame_length(
        preprocessing_frame, input_count * DDNNT_COMPONENT_COUNT);
    preprocessing_guard.release();
    masks_guard.release();
    return masks;
}

std::vector<AuthScalar> receive_ddnnt_offset_and_derive(
        MascotContext& context, client_socket* socket,
        std::span<const AuthScalar> masks, unsigned owner,
        p1_capture::P1OwnerInputOffsetFrameSink* capture) {
    octetStream offset;
    FrameWipeGuard offset_guard(offset);
    offset.Receive(socket);
    bool valid_length = true;
    try { require_owner_fr_frame_length(offset, masks.size()); }
    catch (...) { valid_length = false; }
    const unsigned char valid = valid_length ? 1 : 0;
    context.agree_public_bytes(
        "owner-ddnnt-offset-length-valid",
        std::span<const unsigned char>(&valid, 1));
    if (!valid_length)
        throw std::runtime_error("owner-ddnnt-offset-frame-length");
    if (capture != nullptr)
        capture->owner_input_offset_frame(
            owner, {offset.get_data(), offset.get_length()});
    context.agree_public_bytes(
        "owner-ddnnt-common-offset",
        {offset.get_data(), offset.get_length()});
    auto offsets = decode_owner_fr_frame(offset, masks.size());
    VectorWipeGuard<Fr> offsets_guard(offsets);
    std::vector<AuthScalar> inputs;
    inputs.reserve(masks.size());
    for (std::size_t index = 0; index < masks.size(); ++index)
        inputs.push_back(masks[index] +
                         context.public_constant(offsets[index]));
    context.capture_authenticated_values(
        p1_capture::ScalarCaptureSite::OwnerDerivedInput, inputs);
    return inputs;
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
    if (contract.owner_id < 0 || contract.owner_id > 2 ||
        contract.input_count == 0 ||
        contract.input_count > std::numeric_limits<size_t>::max() /
                                   (DDNNT_COMPONENT_COUNT * Fr::size()))
        throw std::runtime_error("owner-contract-role-or-shape");
    const bool trace_bound = !contract.trace_identity.empty() || !contract.layout_identity.empty();
    if (trace_bound) {
        require_hash(contract.trace_identity);
        require_hash(contract.layout_identity);
    }
    return std::string(trace_bound ? "KPI_MASCOT_OWNER_DDNNT_INPUT_V2\nBN254\nFr\n" :
                                    "KPI_MASCOT_OWNER_DDNNT_INPUT_V1\nBN254\nFr\n") + FR_MODULUS +
        "\nDDNNT_ACTIVE_5N\n" + contract.run_nonce + "\n" +
        contract.model_identity + "\n" + contract.source_identity + "\n" +
        contract.proving_key_identity + "\n" + contract.verifying_key_identity + "\n" +
        (trace_bound ? contract.trace_identity + "\n" + contract.layout_identity + "\n" : "") +
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
    const auto version = token();
    if (version != "KPI_OWNER_DDNNT_CONTRACT_V1" &&
        version != "KPI_OWNER_DDNNT_CONTRACT_V2")
        throw std::runtime_error("owner-contract-version");
    OwnerInputContract result{};
    tag("run_nonce"); result.run_nonce = token();
    tag("model"); result.model_identity = token();
    tag("source"); result.source_identity = token();
    tag("pk"); result.proving_key_identity = token();
    tag("vk"); result.verifying_key_identity = token();
    if (version == "KPI_OWNER_DDNNT_CONTRACT_V2") {
        tag("trace"); result.trace_identity = token();
        tag("layout"); result.layout_identity = token();
    }
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

std::vector<AuthScalar> ActiveOwnerInputServer::receive(
        const OwnerInputContract& contract,
        p1_capture::P1OwnerInputOffsetFrameSink* p1_capture) {
    try {
    auto* attached = context_.p1_capture_seams();
    if (p1_capture != nullptr && attached != nullptr &&
        p1_capture != attached)
        throw std::runtime_error("P1-owner-capture-capability-mismatch");
    auto* selected_capture = p1_capture != nullptr ? p1_capture : attached;
    if (selected_capture != nullptr && context_.party_id() != 1)
        throw std::runtime_error("P1-owner-capture-role");
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

    octetStream preprocessing_frame;
    auto masks = prepare_ddnnt_input_supply(
        context_, contract.input_count, preprocessing_frame);
    try {
        if (selected_capture != nullptr)
            selected_capture->owner_input_preprocessing_share_frame(
                static_cast<unsigned>(contract.owner_id),
                {preprocessing_frame.get_data(),
                 preprocessing_frame.get_length()});
        preprocessing_frame.Send(socket);
        wipe_frame(preprocessing_frame);
        auto inputs = receive_ddnnt_offset_and_derive(
            context_, socket, masks,
            static_cast<unsigned>(contract.owner_id), selected_capture);
        wipe_vector(masks);
        clients_.close_connection(owner);
        return inputs;
    } catch (...) {
        wipe_frame(preprocessing_frame);
        wipe_vector(masks);
        throw;
    }
    } catch (...) { context_.poison(); throw; }
}

std::array<std::vector<AuthScalar>, 3>
ActiveOwnerInputServer::receive_cohort(
        const std::array<OwnerInputContract, 3>& contracts,
        PrivateOwnerCohortObserver& observer,
        p1_capture::P1OwnerInputOffsetFrameSink* p1_capture) {
    try {
    auto* attached = context_.p1_capture_seams();
    if (p1_capture != nullptr && attached != nullptr &&
        p1_capture != attached)
        throw std::runtime_error("P1-owner-capture-capability-mismatch");
    auto* selected_capture = p1_capture != nullptr ? p1_capture : attached;
    if (selected_capture != nullptr && context_.party_id() != 1)
        throw std::runtime_error("P1-owner-capture-role");
    std::array<std::string, 3> canonical;
    std::array<std::size_t, 3> frame_sizes{};
    for (std::size_t role = 0; role < contracts.size(); ++role) {
        const auto& contract = contracts[role];
        if (contract.owner_id != static_cast<int>(role) ||
            !consumed_roles_.insert(contract.owner_id).second)
            throw std::runtime_error("owner-cohort-contract-role");
        canonical[role] = canonical_owner_contract(contract);
        frame_sizes[role] = contract.input_count * Fr::size();
    }
    OwnerCohortIngressState ingress(frame_sizes);

    // Accept and authenticate the complete cohort in arbitrary network order.
    // No MPC agreement or preprocessing is allowed in this phase because the
    // three computing parties can observe different socket arrival orders.
    for (std::size_t ordinal = 0; ordinal < contracts.size(); ++ordinal) {
        const int owner = clients_.get_client_connection(port_base_);
        if (owner < 0 || owner >= static_cast<int>(contracts.size()))
            throw std::runtime_error("owner-cohort-role");
        const auto& contract = contracts[static_cast<std::size_t>(owner)];
        auto* socket = clients_.get_socket(owner);
        const auto owner_key = require_authenticated_peer(
            socket, "C" + std::to_string(owner),
            contract.owner_certificate_sha256);
        if (owner_key == public_key_identity(
                SSL_get_certificate(socket->native_handle())))
            throw std::runtime_error("owner-and-server-TLS-key-reuse");
        ingress.authenticated(static_cast<unsigned>(owner));
        observer.owner_authenticated(static_cast<unsigned>(owner));
        // Upstream Client connects to P0/P1/P2 sequentially and waits for the
        // public job specification at each hop. Send only this already
        // validated owner's canonical public specification now; MPC agreement,
        // preprocessing and private upload remain blocked on the full cohort.
        octetStream specification(canonical[static_cast<std::size_t>(owner)]);
        specification.Send(socket);
    }
    ingress.require_full_authentication();

    // From here every party uses the same canonical role order, independent
    // of its local connection order. This preserves all-three agreement and
    // preprocessing sequencing while keeping arrival order observer-private.
    std::array<std::vector<AuthScalar>, 3> result;
    for (std::size_t role = 0; role < contracts.size(); ++role) {
        const auto& contract = contracts[role];
        const auto& job = canonical[role];
        context_.agree_public_bytes("owner-contract", std::span(
            reinterpret_cast<const unsigned char*>(job.data()), job.size()));
        auto* socket = clients_.get_socket(static_cast<int>(role));
        octetStream acknowledgment;
        acknowledgment.Receive(socket);
        const auto expected_ack = sha256_hex(std::span(
            reinterpret_cast<const unsigned char*>(job.data()), job.size()));
        if (frame_bytes(acknowledgment) != expected_ack)
            throw std::runtime_error(
                "wrong-or-replayed-owner-job-acknowledgment");
        context_.agree_public_bytes("owner-job-ack", std::span(
            acknowledgment.get_data(), acknowledgment.get_length()));

        octetStream preprocessing_frame;
        auto masks = prepare_ddnnt_input_supply(
            context_, contract.input_count, preprocessing_frame);
        try {
            if (selected_capture != nullptr)
                selected_capture->owner_input_preprocessing_share_frame(
                    static_cast<unsigned>(role),
                    {preprocessing_frame.get_data(),
                     preprocessing_frame.get_length()});
            preprocessing_frame.Send(socket);
            wipe_frame(preprocessing_frame);
            result[role] = receive_ddnnt_offset_and_derive(
                context_, socket, masks, static_cast<unsigned>(role),
                selected_capture);
            wipe_vector(masks);
        } catch (...) {
            wipe_frame(preprocessing_frame);
            wipe_vector(masks);
            throw;
        }
        // Count the owner upload only after its exact common offset is
        // canonical, agreed by all three parties and converted to [s] + d.
        ingress.upload_complete(static_cast<unsigned>(role), frame_sizes[role]);
        observer.owner_upload_complete(static_cast<unsigned>(role),
                                       frame_sizes[role]);
        clients_.close_connection(static_cast<int>(role));
    }
    ingress.seal();
    return result;
    } catch (...) { context_.poison(); throw; }
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

    std::array<std::vector<Fr>, 3> party_frames;
    try {
        for (std::size_t server = 0; server < client.sockets.size(); ++server) {
            octetStream frame;
            try {
                frame.Receive(client.sockets[server]);
                party_frames[server] = decode_owner_fr_frame(
                    frame, DDNNT_COMPONENT_COUNT * values.size());
                wipe_frame(frame);
            } catch (...) {
                wipe_frame(frame);
                throw;
            }
        }
        auto masks = reconstruct_checked_ddnnt_masks(
            party_frames, values.size());
        VectorWipeGuard<Fr> masks_guard(masks);
        for (auto& frame : party_frames)
            wipe_owner_fr_values(frame);
        auto offset = make_owner_masked_difference_frame(values, masks);
        FrameWipeGuard offset_guard(offset);
        for (auto* socket : client.sockets)
            offset.Send(socket);
    } catch (...) {
        for (auto& frame : party_frames)
            wipe_owner_fr_values(frame);
        throw;
    }
}
}  // namespace kpi::mpc
