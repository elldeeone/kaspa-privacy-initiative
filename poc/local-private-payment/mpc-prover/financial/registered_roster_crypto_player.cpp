#include "registered_roster_crypto_player.hpp"
#ifdef KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1
#include "registered_p1_state_archive_scm.hpp"
#endif

#include <algorithm>
#include <cctype>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <set>
#include <span>
#include <utility>
#include <vector>

namespace kpi::mpc::financial {
namespace {

using Bytes = std::vector<unsigned char>;

[[noreturn]] void refuse() { throw history::Refused(); }
void need(bool value) { if (!value) refuse(); }
bool nonzero(const history::Digest& value) {
    return value != history::Digest{};
}
void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add(Bytes& out, const std::string& value) {
    out.insert(out.end(), value.begin(), value.end());
}
void integer(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}
void string(Bytes& out, const std::string& value) {
    integer(out, value.size());
    add(out, value);
}

bool uuid_v4(const std::string& value) {
    if (value.size() != 36 || value[8] != '-' || value[13] != '-' ||
        value[18] != '-' || value[23] != '-' || value[14] != '4' ||
        std::string("89ab").find(value[19]) == std::string::npos)
        return false;
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (index == 8 || index == 13 || index == 18 || index == 23) continue;
        const unsigned char byte = value[index];
        if (!std::isdigit(byte) && !(byte >= 'a' && byte <= 'f')) return false;
    }
    return true;
}

std::array<const history::Digest*, 24> binding_digests(
        const RegisteredRosterBinding& value) {
    return {
        &value.selection_candidate, &value.registration,
        &value.trial_authority, &value.ready_checkpoint,
        &value.certificate_authority, &value.server_certificates[0],
        &value.server_certificates[1], &value.server_certificates[2],
        &value.accepted_head_source_closure, &value.accepted_head_build,
        &value.exporter_adapter, &value.exporter_source_closure,
        &value.exporter_build, &value.qualifier_source_closure,
        &value.qualifier_build, &value.qualifier_authority_build,
        &value.qualifier_build_contract,
        &value.qualifier_configuration_selection,
        &value.native_parameters, &value.immutable_tail,
        &value.component_profile, &value.outer_image,
        &value.native_program, &value.native_codec,
    };
}

void valid(const PublicImmutableRosterSelection& value) {
    need(value.role < 3 && value.port_base >= 1024 &&
         value.port_base <= 65533 &&
         uuid_v4(value.registered_binding.trial_id) &&
         value.server_certificates ==
             value.registered_binding.server_certificates);
    for (const auto& host : value.hosts)
        need(!host.empty() && host.size() <= 253 &&
             host.find('\0') == std::string::npos);
    for (const auto* digest : binding_digests(value.registered_binding))
        need(nonzero(*digest));
    need(std::set<history::Digest>(
             value.server_certificates.begin(),
             value.server_certificates.end()).size() == 3);
    for (const auto* digest : {
             &value.transport_source_identity,
             &value.transport_build_identity,
             &value.transport_launcher_identity}) need(nonzero(*digest));
    need(value.transport_source_identity != value.transport_build_identity &&
         value.transport_source_identity != value.transport_launcher_identity &&
         value.transport_build_identity != value.transport_launcher_identity);
}

void add_binding(Bytes& out, const RegisteredRosterBinding& value) {
    string(out, value.trial_id);
    for (const auto* digest : binding_digests(value)) add(out, *digest);
}

history::Digest compute_transport_identity(
        const PublicImmutableRosterSelection& value) {
    Bytes bytes;
    const std::string tag = "KPB_REGISTERED_IMMUTABLE_ROSTER_V1\n";
    add(bytes, tag);
    for (const auto& host : value.hosts) string(bytes, host);
    integer(bytes, static_cast<std::uint64_t>(value.port_base));
    add_binding(bytes, value.registered_binding);
    add(bytes, value.transport_source_identity);
    add(bytes, value.transport_build_identity);
    add(bytes, value.transport_launcher_identity);
    return history::digest(bytes);
}

history::Digest authority_identity(
        const PublicImmutableRosterSelection& value,
        const history::Digest& transport) {
    Bytes bytes;
    const std::string tag =
        "KPB_REGISTERED_IMMUTABLE_ROSTER_ROLE_AUTHORITY_V1\n";
    add(bytes, tag);
    add(bytes, transport);
    integer(bytes, value.role);
    return history::digest(bytes);
}

void require_names(
        const ::Names& names,
        const PublicImmutableRosterSelection& selection) {
    need(names.my_num() == static_cast<int>(selection.role) &&
         names.num_players() == 3 &&
         names.get_portnum_base() == selection.port_base);
    for (unsigned role = 0; role < 3; ++role)
        need(names.get_name(static_cast<int>(role)) == selection.hosts[role]);
}

history::Digest certificate_digest(X509* certificate) {
    need(certificate != nullptr);
    unsigned char* raw = nullptr;
    const int size = i2d_X509(certificate, &raw);
    need(size > 0 && raw != nullptr);
    const auto result = history::digest(std::span(raw, size));
    OPENSSL_free(raw);
    return result;
}

void require_name(X509* certificate, unsigned role) {
    const auto expected = "P" + std::to_string(role);
    need(X509_check_host(certificate, expected.c_str(), expected.size(),
                         0, nullptr) == 1);
}

void require_verified_chain_ca(
        SSL* ssl, const history::Digest& expected_ca) {
    STACK_OF(X509)* chain = SSL_get0_verified_chain(ssl);
    need(chain != nullptr && sk_X509_num(chain) >= 2);
    X509* root = sk_X509_value(chain, sk_X509_num(chain) - 1);
    need(root != nullptr && certificate_digest(root) == expected_ca);
}

#ifdef KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1
p1_private_state::PlayerTlsEventView player_event(
        p1_private_state::PlayerTlsEventKind kind,
        const PublicImmutableRosterSelection& selection,
        std::string_view player_id, std::string_view parent_id = {}) {
    p1_private_state::PlayerTlsEventView result{};
    result.kind = kind;
    result.local_role = selection.role;
    result.player_count = selection.hosts.size();
    result.player_id = player_id;
    result.parent_player_id = parent_id;
    return result;
}

void require_player_event(
        p1_private_state::PlayerTlsStateHook& hook,
        const p1_private_state::PlayerTlsEventView& event) {
    need(hook.record_player_tls_event(event));
}
#endif

} // namespace

ImmutableRegisteredRosterAuthority::ImmutableRegisteredRosterAuthority(
        PublicImmutableRosterSelection value)
    : value_(std::move(value)) {
    valid(value_);
    transport_identity_ = compute_transport_identity(value_);
    authority_identity_ = authority_identity(value_, transport_identity_);
    need(nonzero(transport_identity_) && nonzero(authority_identity_) &&
         transport_identity_ != authority_identity_);
}

void ImmutableRegisteredRosterAuthority::require_valid_for_capture_plan()
        const {
    valid(value_);
    const auto transport = compute_transport_identity(value_);
    const auto authority = authority_identity(value_, transport);
    need(nonzero(transport) && nonzero(authority) &&
         transport == transport_identity_ &&
         authority == authority_identity_ && transport != authority);
}

ImmutableRegisteredRosterAuthority::ImmutableRegisteredRosterAuthority(
        ImmutableRegisteredRosterAuthority&& other) noexcept
    : value_(std::move(other.value_)),
      authority_identity_(other.authority_identity_),
      transport_identity_(other.transport_identity_),
      live_(other.live_.exchange(false)) {}

#ifdef KPI_REGISTERED_ROSTER_TEST_SETUP
ImmutableRegisteredRosterAuthority
ImmutableRegisteredRosterAuthority::test_only_mint(
        PublicImmutableRosterSelection value) {
    return ImmutableRegisteredRosterAuthority(std::move(value));
}
#endif

RegisteredRosterCryptoPlayer::RegisteredRosterCryptoPlayer(
        const ::Names& names, PublicImmutableRosterSelection selection,
        history::Digest selected_transport_identity, std::string id)
    : ::CryptoPlayer(names, id), selection_(std::move(selection)),
      transport_identity_(selected_transport_identity) {
    verify_live_roster_and_agree_binding();
}

#ifdef KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1
RegisteredRosterCryptoPlayer::RegisteredRosterCryptoPlayer(
        const ::Names& names, PublicImmutableRosterSelection selection,
        history::Digest selected_transport_identity, std::string id,
        std::string parent_id,
        p1_private_state::PlayerTlsStateHook& player_tls_state)
    : ::CryptoPlayer(names, id, &player_tls_state),
      selection_(std::move(selection)),
      transport_identity_(selected_transport_identity),
      player_tls_state_(&player_tls_state), source_player_id_(std::move(id)) {
    (void)parent_id;
    verify_live_roster_and_agree_binding();
    require_player_event(
        player_tls_state,
        player_event(
            p1_private_state::PlayerTlsEventKind::PlayerConstructed,
            selection_, source_player_id_));
}

RegisteredRosterCryptoPlayer::~RegisteredRosterCryptoPlayer() {
    if (!player_tls_state_) return;
    const auto event = player_event(
        p1_private_state::PlayerTlsEventKind::PlayerDestructionStarted,
        selection_, source_player_id_);
    if (!player_tls_state_->record_player_tls_event(event))
        player_tls_state_->player_tls_unavailable_noexcept();
}
#endif

std::unique_ptr<RegisteredRosterCryptoPlayer>
RegisteredRosterCryptoPlayer::begin(
        const ::Names& names,
        ImmutableRegisteredRosterAuthority&& authority) {
    try {
        need(authority.live_.exchange(false));
        valid(authority.value_);
        need(authority.transport_identity_ ==
                 compute_transport_identity(authority.value_) &&
             authority.authority_identity_ ==
                 authority_identity(
                     authority.value_, authority.transport_identity_));
        require_names(names, authority.value_);
        return std::unique_ptr<RegisteredRosterCryptoPlayer>(
            new RegisteredRosterCryptoPlayer(
                names, authority.value_, authority.transport_identity_,
                "registered-roster"));
    } catch (...) { refuse(); }
}

#ifdef KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1
std::unique_ptr<RegisteredRosterCryptoPlayer>
RegisteredRosterCryptoPlayer::begin(
        const ::Names& names,
        ImmutableRegisteredRosterAuthority&& authority,
        p1_private_state::PlayerTlsStateHook& player_tls_state) {
    try {
        need(authority.live_.exchange(false));
        valid(authority.value_);
        need(authority.value_.role == 1 &&
             authority.transport_identity_ ==
                 compute_transport_identity(authority.value_) &&
             authority.authority_identity_ == authority_identity(
                 authority.value_, authority.transport_identity_));
        require_names(names, authority.value_);
        const std::string id = "registered-roster";
        require_player_event(
            player_tls_state,
            player_event(
                p1_private_state::PlayerTlsEventKind::
                    PlayerConstructionStarted,
                authority.value_, id));
        return std::unique_ptr<RegisteredRosterCryptoPlayer>(
            new RegisteredRosterCryptoPlayer(
                names, authority.value_, authority.transport_identity_, id,
                {}, player_tls_state));
    } catch (...) {
        player_tls_state.player_tls_unavailable_noexcept();
        refuse();
    }
}
#endif

RegisteredRosterPlayerRuntime::RegisteredRosterPlayerRuntime(
        std::unique_ptr<::Names> names,
        std::unique_ptr<RegisteredRosterCryptoPlayer> player)
    : names_(std::move(names)), player_(std::move(player)) {
    need(names_ != nullptr && player_ != nullptr &&
         &player_->N == names_.get());
}

#ifdef KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1
RegisteredRosterPlayerRuntime::RegisteredRosterPlayerRuntime(
        std::unique_ptr<::Names> names,
        std::unique_ptr<
            kpb::measurement::p1_state_capsule::P1PlayerTlsStateAdapter>
            player_tls_state,
        std::unique_ptr<RegisteredRosterCryptoPlayer> player)
    : names_(std::move(names)),
      player_tls_state_(std::move(player_tls_state)),
      player_(std::move(player)) {
    need(names_ != nullptr && player_tls_state_ != nullptr &&
         player_ != nullptr && &player_->N == names_.get());
}
#endif

std::unique_ptr<RegisteredRosterPlayerRuntime>
RegisteredRosterPlayerRuntime::begin_after_fork(
        ImmutableRegisteredRosterAuthority&& authority) {
    try {
        need(authority.live_.load());
        valid(authority.value_);
        const auto role = authority.value_.role;
        const auto port = authority.value_.port_base;
        std::vector<std::string> hosts(
            authority.value_.hosts.begin(), authority.value_.hosts.end());
        auto names = std::make_unique<::Names>(
            static_cast<int>(role), port, std::move(hosts));
        auto player = RegisteredRosterCryptoPlayer::begin(
            *names, std::move(authority));
        return std::unique_ptr<RegisteredRosterPlayerRuntime>(
            new RegisteredRosterPlayerRuntime(
                std::move(names), std::move(player)));
    } catch (...) { refuse(); }
}

#ifdef KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1
std::unique_ptr<RegisteredRosterPlayerRuntime>
RegisteredRosterPlayerRuntime::begin_after_fork(
        ImmutableRegisteredRosterAuthority&& authority,
        registered_driver::RegisteredRole1P1StateRecorderFacade&
            private_state,
        const kpb::measurement::p1_state_capsule::
            P1StateThreadEpochAuthority& root_thread) {
    using kpb::measurement::p1_state_capsule::SourcePhase;
    try {
        need(authority.live_.load());
        valid(authority.value_);
        need(authority.value_.role == 1);
        const auto role = authority.value_.role;
        const auto port = authority.value_.port_base;
        std::vector<std::string> hosts(
            authority.value_.hosts.begin(), authority.value_.hosts.end());
        auto player_tls_state =
            private_state.take_player_tls_state_adapter(root_thread);
        auto names = std::make_unique<::Names>(
            static_cast<int>(role), port, std::move(hosts));
        auto player = RegisteredRosterCryptoPlayer::begin(
            *names, std::move(authority), *player_tls_state);
        private_state.advance_phase(SourcePhase::TlsAndPlayerBound);
        return std::unique_ptr<RegisteredRosterPlayerRuntime>(
            new RegisteredRosterPlayerRuntime(
                std::move(names), std::move(player_tls_state),
                std::move(player)));
    } catch (...) { refuse(); }
}
#endif

void RegisteredRosterCryptoPlayer::require_live_tls_channels() {
    const auto require_live_lane = [&](ssl_socket* socket, unsigned peer) {
        need(socket != nullptr);
        SSL* ssl = socket->native_handle();
        need(ssl != nullptr && SSL_get_verify_result(ssl) == X509_V_OK);
        require_verified_chain_ca(
            ssl, selection_.registered_binding.certificate_authority);
        X509* local = SSL_get_certificate(ssl);
        need(local != nullptr &&
             certificate_digest(local) ==
                 selection_.server_certificates[selection_.role]);
        require_name(local, selection_.role);
        std::unique_ptr<X509, decltype(&X509_free)> remote(
            SSL_get1_peer_certificate(ssl), X509_free);
        need(bool(remote) &&
             certificate_digest(remote.get()) ==
                 selection_.server_certificates[peer]);
        require_name(remote.get(), peer);
    };

    for (unsigned peer = 0; peer < 3; ++peer) {
        if (peer == selection_.role) continue;
#ifdef KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1
        auto* lane0 = p1_tls_socket(peer, 0);
        auto* lane1 = p1_tls_socket(peer, 1);
        need(lane0 != nullptr && lane1 != nullptr && lane0 != lane1 &&
             lane0->native_handle() != lane1->native_handle());
        require_live_lane(lane0, peer);
        require_live_lane(lane1, peer);
#else
        require_live_lane(sockets.at(peer), peer);
#endif
    }
}

#if defined(KPI_REGISTERED_ROSTER_TEST_SETUP) && \
    defined(KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1)
void RegisteredRosterCryptoPlayer::test_only_require_tls_lane_fault_refuses(
        TestOnlyTlsLaneFault fault) {
    const unsigned peer = (selection_.role + 1) % 3;
    const unsigned other_peer = (selection_.role + 2) % 3;
    ssl_socket* replacement = nullptr;
    switch (fault) {
    case TestOnlyTlsLaneFault::Missing:
        break;
    case TestOnlyTlsLaneFault::Duplicate:
        replacement = p1_tls_socket(peer, 0);
        break;
    case TestOnlyTlsLaneFault::SubstitutedPeer:
        replacement = p1_tls_socket(other_peer, 1);
        break;
    }
    auto* original = p1_test_replace_tls_socket(peer, 1, replacement);
    struct Restore final {
        RegisteredRosterCryptoPlayer* player;
        unsigned peer;
        ssl_socket* original;
        ~Restore() {
            (void)player->p1_test_replace_tls_socket(peer, 1, original);
        }
    } restore{this, peer, original};
    require_live_tls_channels();
}
#endif

void RegisteredRosterCryptoPlayer::verify_live_roster_and_agree_binding() {
    try {
        valid(selection_);
        require_names(N, selection_);
        need(is_encrypted() && my_num() == static_cast<int>(selection_.role) &&
             num_players() == 3 &&
             transport_identity_ == compute_transport_identity(selection_));
        require_live_tls_channels();

        std::vector<octetStream> agreement(3);
        agreement.at(selection_.role).append(
            transport_identity_.data(), transport_identity_.size());
        Broadcast_Receive(agreement);
        for (const auto& observed : agreement)
            need(observed.get_length() == transport_identity_.size() &&
                 std::memcmp(observed.get_data(), transport_identity_.data(),
                             transport_identity_.size()) == 0);
    } catch (...) { refuse(); }
}

const std::array<history::Digest, 3>&
RegisteredRosterCryptoPlayer::authenticated_roster() const noexcept {
    return selection_.server_certificates;
}

const RegisteredRosterBinding&
RegisteredRosterCryptoPlayer::authenticated_registered_binding()
        const noexcept {
    return selection_.registered_binding;
}

::Player* RegisteredRosterCryptoPlayer::fresh_fork(std::string suffix) {
    try {
        need(!suffix.empty() && suffix.size() <= 128);
#ifdef KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1
        if (player_tls_state_ != nullptr) {
            const auto id = get_id() + "-" + suffix;
            require_player_event(
                *player_tls_state_,
                player_event(
                    p1_private_state::PlayerTlsEventKind::
                        PlayerConstructionStarted,
                    selection_, id, source_player_id_));
            return new RegisteredRosterCryptoPlayer(
                N, selection_, transport_identity_, id, source_player_id_,
                *player_tls_state_);
        }
#endif
        return new RegisteredRosterCryptoPlayer(
            N, selection_, transport_identity_, get_id() + "-" + suffix);
    } catch (...) {
#ifdef KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1
        if (player_tls_state_ != nullptr)
            player_tls_state_->player_tls_unavailable_noexcept();
#endif
        refuse();
    }
}

RegisteredRosterCryptoPlayerSourceStatus
registered_roster_crypto_player_source_status() {
#ifdef KPB_MP_SPDZ_P1_PLAYER_TLS_HOOK_V1
    constexpr bool source_hook = true;
#else
    constexpr bool source_hook = false;
#endif
    return {
        .schema = "kpb-registered-roster-crypto-player-source-only/v1",
        .status = "UNQUALIFIED_SOURCE_ONLY",
        .live_tls_certificate_authority_verified = true,
        // The unpatched legacy build can inspect only MultiPlayer::sockets.
        // The source-pinned observer patch exposes and exact-checks both
        // CryptoPlayer TLS lanes.  Do not overstate the legacy path.
        .live_tls_peer_certificate_der_verified = source_hook,
        .exact_three_role_binding_agreement = true,
        .mp_spdz_fork_preserves_roster = true,
        .source_pinned_player_tls_hook = source_hook,
        .private_state_runtime_overload = source_hook,
        .openssl_complete_private_state = false,
        .accepts_argv_or_environment = false,
        .selected_authority_factory_integration = false,
        .selected_gate_callsite_integration = false,
        .registered_driver_configured = false,
        .launch_authorized = false,
    };
}

} // namespace kpi::mpc::financial
