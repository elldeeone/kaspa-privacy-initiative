#include "../registered_roster_crypto_player.hpp"

#include <array>
#include <atomic>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <new>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <string>

using namespace kpi::mpc::financial;
namespace history = kpi::mpc::history;

namespace {

std::atomic_bool deny_allocations{};

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
    assert(file);
    std::unique_ptr<X509, decltype(&X509_free)> certificate(
        PEM_read_X509(file.get(), nullptr, nullptr, nullptr), X509_free);
    assert(certificate);
    unsigned char* raw = nullptr;
    const int size = i2d_X509(certificate.get(), &raw);
    assert(size > 0 && raw != nullptr);
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

PublicImmutableRosterSelection selection(
        unsigned role, int port, const std::string& scenario) {
    std::array<history::Digest, 3> roster{
        certificate_digest("Player-Data/P0.pem"),
        certificate_digest("Player-Data/P1.pem"),
        certificate_digest("Player-Data/P2.pem"),
    };
    if (scenario == "wrong-roster") roster[0] = id(99);
    auto ca = certificate_digest("Player-Data/ca.pem");
    if (scenario == "wrong-ca") ca = id(98);
    auto selected_binding = binding(roster, ca);
    if (scenario == "mixed-binding" && role == 2)
        selected_binding.component_profile = id(77);
    return {
        .role = role,
        .hosts = {"127.0.0.1", "127.0.0.1", "127.0.0.1"},
        .port_base = port,
        .server_certificates = roster,
        .registered_binding = std::move(selected_binding),
        .transport_source_identity = id(30),
        .transport_build_identity = id(31),
        .transport_launcher_identity = id(32),
    };
}

template<class Callable>
bool refuses(Callable&& callable) {
    try {
        callable();
    } catch (const history::Refused&) {
        return true;
    }
    return false;
}

int invalid_selection(const std::string& scenario) {
    auto value = selection(0, 32100, "valid");
    if (scenario == "invalid-role") value.role = 3;
    else if (scenario == "duplicate-roster")
        value.server_certificates[2] = value.server_certificates[1];
    else if (scenario == "binding-roster-mismatch")
        value.registered_binding.server_certificates[0] = id(88);
    else return 64;
    return refuses([&] {
        (void)ImmutableRegisteredRosterAuthority::test_only_mint(
            std::move(value));
    }) ? 0 : 1;
}

int noalloc_authority_move() {
    auto authority = ImmutableRegisteredRosterAuthority::test_only_mint(
        selection(0, 32100, "valid"));
    deny_allocations.store(true, std::memory_order_relaxed);
    auto moved = ImmutableRegisteredRosterAuthority(std::move(authority));
    deny_allocations.store(false, std::memory_order_relaxed);
    (void)moved;
    return 0;
}

} // namespace

void* operator new(std::size_t size) {
    if (deny_allocations.load(std::memory_order_relaxed))
        throw std::bad_alloc();
    if (void* value = std::malloc(size == 0 ? 1 : size)) return value;
    throw std::bad_alloc();
}
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete(void* value) noexcept { std::free(value); }
void operator delete[](void* value) noexcept { std::free(value); }
void operator delete(void* value, std::size_t) noexcept { std::free(value); }
void operator delete[](void* value, std::size_t) noexcept {
    std::free(value);
}

int main(int argc, char** argv) {
    if (argc == 2 && std::string(argv[1]) == "noalloc-move")
        return noalloc_authority_move();
    if (argc == 2) return invalid_selection(argv[1]);
    if (argc != 4) return 64;
    const unsigned role = static_cast<unsigned>(std::stoul(argv[1]));
    const int port = std::stoi(argv[2]);
    const std::string scenario(argv[3]);
    try {
        auto value = selection(role, port, scenario);
        const auto expected_roster = value.server_certificates;
        const auto expected_binding = value.registered_binding;
        auto authority = ImmutableRegisteredRosterAuthority::test_only_mint(
            std::move(value));
        std::unique_ptr<RegisteredRosterPlayerRuntime> runtime;
        std::unique_ptr<Names> names;
        std::unique_ptr<RegisteredRosterCryptoPlayer> direct_player;
        RegisteredRosterCryptoPlayer* player = nullptr;
        if (scenario == "runtime") {
            runtime = RegisteredRosterPlayerRuntime::begin_after_fork(
                std::move(authority));
            player = &runtime->player();
        } else {
            names = std::make_unique<Names>(
                static_cast<int>(role), 3, "127.0.0.1", port);
            direct_player = RegisteredRosterCryptoPlayer::begin(
                *names, std::move(authority));
            player = direct_player.get();
        }
#ifdef KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1
        using Fault =
            RegisteredRosterCryptoPlayer::TestOnlyTlsLaneFault;
        if (scenario == "missing-secondary-lane")
            return refuses([&] {
                player->test_only_require_tls_lane_fault_refuses(
                    Fault::Missing);
            }) ? 0 : 6;
        if (scenario == "duplicate-secondary-lane")
            return refuses([&] {
                player->test_only_require_tls_lane_fault_refuses(
                    Fault::Duplicate);
            }) ? 0 : 7;
        if (scenario == "substituted-secondary-lane")
            return refuses([&] {
                player->test_only_require_tls_lane_fault_refuses(
                    Fault::SubstitutedPeer);
            }) ? 0 : 8;
#endif
        if (scenario != "valid" && scenario != "runtime") return 2;
        if (!player || !player->is_encrypted() ||
            player->my_num() != static_cast<int>(role) ||
            player->num_players() != 3 ||
            player->authenticated_roster() != expected_roster ||
            player->authenticated_registered_binding() != expected_binding ||
            player->transport_identity() == history::Digest{}) return 3;

        std::unique_ptr<Player> forked(player->fresh_fork("nested"));
        auto* roster = dynamic_cast<RosterPinnedPlayer*>(forked.get());
        if (!roster || !forked->is_encrypted() ||
            roster->authenticated_roster() != expected_roster ||
            roster->authenticated_registered_binding() != expected_binding)
            return 4;
        if (!refuses([&] {
                if (names)
                    (void)RegisteredRosterCryptoPlayer::begin(
                        *names, std::move(authority));
                else
                    (void)RegisteredRosterPlayerRuntime::begin_after_fork(
                        std::move(authority));
            })) return 5;
        return 0;
    } catch (...) {
        return (scenario == "valid" || scenario == "runtime") ? 78 : 0;
    }
}
