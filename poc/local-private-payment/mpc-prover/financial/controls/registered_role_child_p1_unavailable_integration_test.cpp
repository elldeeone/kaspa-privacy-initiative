#include "../registered_p1_state_archive_scm.hpp"
#include "../registered_roster_crypto_player.hpp"
#include "../../../private_batch_trial/privacy_p1_corrupt_state_capsule_test_fixture.hpp"
#include "../../../private_batch_trial/privacy_registered_fresh_trial_capture_topology_reservation.hpp"

#include <array>
#include <cassert>
#include <cstdio>
#include <memory>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>

using namespace kpi::mpc::financial;
using namespace kpi::mpc::financial::registered_driver;
namespace history = kpi::mpc::history;

namespace {

int selected_port{};
bool expect_tls_success{};

struct FileCloser final {
    void operator()(FILE* value) const noexcept {
        if (value != nullptr) std::fclose(value);
    }
};

history::Digest id(unsigned value) {
    history::Digest result{};
    result[0] = static_cast<unsigned char>(value);
    result[1] = static_cast<unsigned char>(value >> 8);
    result[31] = static_cast<unsigned char>(value ^ 0xc7U);
    return result;
}

history::Digest certificate_digest(const std::string& path) {
    std::unique_ptr<FILE, FileCloser> file(std::fopen(path.c_str(), "rb"));
    if (!file) throw std::runtime_error("missing-test-certificate");
    std::unique_ptr<X509, decltype(&X509_free)> certificate(
        PEM_read_X509(file.get(), nullptr, nullptr, nullptr), X509_free);
    if (!certificate) throw std::runtime_error("invalid-test-certificate");
    unsigned char* raw = nullptr;
    const int size = i2d_X509(certificate.get(), &raw);
    if (size <= 0 || raw == nullptr)
        throw std::runtime_error("invalid-test-certificate-DER");
    const auto result = history::digest(std::span(raw, size));
    OPENSSL_free(raw);
    return result;
}

RegisteredRosterBinding binding(
        const std::array<history::Digest, 3>& roster,
        const history::Digest& certificate_authority) {
    return {
        .trial_id = "123e4567-e89b-42d3-a456-426614174000",
        .selection_candidate = id(1),
        .registration = id(2),
        .trial_authority = id(3),
        .ready_checkpoint = id(4),
        .certificate_authority = certificate_authority,
        .server_certificates = roster,
        .accepted_head_source_closure = id(6),
        .accepted_head_build = id(7),
        .exporter_adapter = id(8),
        .exporter_source_closure = id(9),
        .exporter_build = id(10),
        .qualifier_source_closure = id(11),
        .qualifier_build = id(12),
        .qualifier_authority_build = id(13),
        .qualifier_build_contract = id(14),
        .qualifier_configuration_selection = id(15),
        .native_parameters = id(16),
        .immutable_tail = id(17),
        .component_profile = id(18),
        .outer_image = id(19),
        .native_program = id(20),
        .native_codec = id(21),
    };
}

PublicImmutableRosterSelection selection(unsigned role, int port) {
    const std::array<history::Digest, 3> roster{
        certificate_digest("Player-Data/P0.pem"),
        certificate_digest("Player-Data/P1.pem"),
        certificate_digest("Player-Data/P2.pem"),
    };
    const auto ca = certificate_digest("Player-Data/ca.pem");
    return {
        .role = role,
        .hosts = {"127.0.0.1", "127.0.0.1", "127.0.0.1"},
        .port_base = port,
        .server_certificates = roster,
        .registered_binding = binding(roster, ca),
        .transport_source_identity = id(30),
        .transport_build_identity = id(31),
        .transport_launcher_identity = id(32),
    };
}

void allocation_gate(bool) noexcept {}

[[noreturn]] void real_tls_failure_probe(
        RegisteredRole1P1StateRecorderFacade& private_state) {
    auto root_thread = private_state.take_root_thread_epoch();
    auto authority = ImmutableRegisteredRosterAuthority::test_only_mint(
        selection(1, selected_port));
    // P2's certificate is signed by the selected CA but has the deliberately
    // wrong DNS name in the hostile case. This reaches the genuine OpenSSL
    // hostname verifier and patched handshake-failure callback; it is not a
    // caller-thrown fault.
    auto roster = RegisteredRosterPlayerRuntime::begin_after_fork(
        std::move(authority), private_state, root_thread);
    if (expect_tls_success) {
        assert(roster != nullptr && roster->player().is_encrypted() &&
               roster->player().my_num() == 1 &&
               roster->player().num_players() == 3);
        std::fputs("KPB_TLS_FOUR_LANE_ATTACHED\n", stderr);
        std::fflush(stderr);
        throw std::runtime_error("control-unwind-after-four-lane-attachment");
    }
    throw std::runtime_error("TLS-handshake-unexpectedly-succeeded");
}

int peer(unsigned role, int port) {
    try {
        auto authority = ImmutableRegisteredRosterAuthority::test_only_mint(
            selection(role, port));
        (void)RegisteredRosterPlayerRuntime::begin_after_fork(
            std::move(authority));
        return 0;
    } catch (...) {
        return 78;
    }
}

int integration(int port, bool success) {
    selected_port = port;
    expect_tls_success = success;
    auto reservation = FreshTrialCaptureTopologyReservationBridge::
        test_only_reserve_unbound();
    auto topology = std::move(reservation)
        .test_only_take_activation_transfer();
    const auto summary = RegisteredP1StateArchiveScmBridge::test_only_run(
        topology,
        RegisteredP1StateArchiveScmTestFault::RuntimeFailureProbeThrows,
        &kpb::measurement::p1_state_capsule::test_fixture::
            closed_unavailable_adopting,
        &kpb::measurement::p1_state_capsule::test_fixture::
            wrong_round_adoption_refused,
        &kpb::measurement::p1_state_capsule::test_fixture::
            wrong_reservation_adoption_refused,
        &kpb::measurement::p1_state_capsule::test_fixture::
            matching_plan_for_adoption,
        &allocation_gate, &real_tls_failure_probe);
    assert(summary.expected_result);
    assert(summary.authenticated_activation_acks == 2);
    assert(summary.typed_authenticated_dispositions == 1);
    assert(summary.typed_same_inode_dispositions == 1);
    assert(summary.terminal_ack_before_pidfd_wait);
    assert(summary.exact_two_parent_reads_retained);
    assert(summary.child_exited && summary.child_exit_code != 0 &&
           summary.child_exit_code != 1);
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc == 3 && std::string(argv[1]) == "integration-failure")
        return integration(std::stoi(argv[2]), false);
    if (argc == 3 && std::string(argv[1]) == "integration-success")
        return integration(std::stoi(argv[2]), true);
    if (argc == 4 && std::string(argv[1]) == "peer")
        return peer(static_cast<unsigned>(std::stoul(argv[2])),
                    std::stoi(argv[3]));
    return 64;
}

