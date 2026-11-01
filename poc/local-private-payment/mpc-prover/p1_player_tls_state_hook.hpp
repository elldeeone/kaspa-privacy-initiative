#pragma once

// Source-only observer-v5 hook surface for the selected corrupt-P1
// CryptoPlayer construction prefix. The concrete capsule adapter records raw
// private key/session material into the private state archive, never into C03
// or a public receipt. This interface is evidence transport, not authority.
// The selected source manifest must still pin every genuine caller.

#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace kpb::measurement::p1_state_capsule {
class P1CorruptStateRecorderAuthority;
class P1StateThreadEpochAuthority;
class P1PlayerTlsStateAdapter;

// Complete before either private friendship grant. The exact class is the
// sole constructor bridge from a live recorder into the shared-ledger adapter.
class P1PlayerTlsStateAdapterFactoryBridge final {
    P1PlayerTlsStateAdapterFactoryBridge() = delete;
public:
    static std::unique_ptr<P1PlayerTlsStateAdapter> take(
        P1CorruptStateRecorderAuthority&,
        const P1StateThreadEpochAuthority&);
};
}

namespace kpi::mpc::p1_private_state {

enum class PlayerTlsEventKind : std::uint8_t {
    PlayerConstructionStarted = 1,
    PlayerConstructed = 2,
    PlayerDestructionStarted = 3,
    TlsContextLoaded = 4,
    TlsChannelStarted = 5,
    TlsInfo = 6,
    TlsMessage = 7,
    TlsKeyLog = 8,
    TlsHandshakeComplete = 9,
    TlsHandshakeFailed = 10,
};

inline constexpr std::uint64_t NO_TLS_PEER =
    std::numeric_limits<std::uint64_t>::max();
inline constexpr std::uint64_t NO_TLS_LANE =
    std::numeric_limits<std::uint64_t>::max();

// Payload meanings are fixed by kind:
//
//   ContextLoaded:       [certificate DER, private-key DER]
//   TlsMessage:          [exact OpenSSL message-callback bytes]
//   TlsKeyLog:           [exact NSS key-log line, without a trailing NUL]
//   HandshakeComplete:   [client random, server random, master key,
//                         session id, local certificate DER,
//                         canonical verified-chain DER vector]
//   all other kinds:     every payload is empty
//
// The verified-chain vector is u64(count), then repeated
// u64(DER bytes)||DER. Integers within this view are encoded as big-endian
// u64. No pointer, file path, environment value, or caller-created digest is
// accepted as a substitute for the raw state bytes.
struct PlayerTlsEventView final {
    PlayerTlsEventKind kind{};
    std::uint64_t local_role{};
    std::uint64_t player_count{};
    std::uint64_t peer_role{NO_TLS_PEER};
    std::uint64_t lane{NO_TLS_LANE};
    std::uint64_t client{};
    std::uint64_t write_direction{};
    std::uint64_t protocol_version{};
    std::uint64_t content_type{};
    std::uint64_t info_where{};
    std::uint64_t info_return{};
    std::uint64_t verify_result{};
    std::uint64_t ssl_state{};
    std::uint64_t shutdown_state{};
    std::string_view player_id;
    std::string_view parent_player_id;
    std::string_view protocol_name;
    std::string_view cipher_name;
    std::string_view failure_class;
    std::array<std::span<const unsigned char>, 6> payloads{};
};

namespace player_tls_detail {

inline void append_u64(
        std::vector<unsigned char>& output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        output.push_back(static_cast<unsigned char>(value >> shift));
}

inline void append_bytes(
        std::vector<unsigned char>& output,
        std::span<const unsigned char> value) {
    if (value.size() > std::numeric_limits<std::uint64_t>::max() ||
        output.size() > std::numeric_limits<std::size_t>::max() - 8 ||
        value.size() >
            std::numeric_limits<std::size_t>::max() - output.size() - 8)
        throw std::runtime_error("P1-player-TLS-state-size-overflow");
    append_u64(output, value.size());
    output.insert(output.end(), value.begin(), value.end());
}

inline void append_string(
        std::vector<unsigned char>& output, std::string_view value) {
    append_bytes(output, std::span(
        reinterpret_cast<const unsigned char*>(value.data()),
        value.size()));
}

inline bool empty_payloads(const PlayerTlsEventView& value) {
    for (const auto payload : value.payloads)
        if (!payload.empty()) return false;
    return true;
}

} // namespace player_tls_detail

inline std::vector<unsigned char> encode_player_tls_event(
        const PlayerTlsEventView& value) {
    const auto kind = static_cast<unsigned>(value.kind);
    if (kind < static_cast<unsigned>(
                   PlayerTlsEventKind::PlayerConstructionStarted) ||
        kind > static_cast<unsigned>(
                   PlayerTlsEventKind::TlsHandshakeFailed) ||
        value.player_count != 3 || value.local_role != 1 ||
        value.player_id.empty() ||
        value.player_id.find('\0') != std::string_view::npos ||
        value.parent_player_id.find('\0') != std::string_view::npos ||
        value.protocol_name.find('\0') != std::string_view::npos ||
        value.cipher_name.find('\0') != std::string_view::npos ||
        value.failure_class.find('\0') != std::string_view::npos)
        throw std::runtime_error("invalid-P1-player-TLS-state-event");

    const bool channel =
        value.kind == PlayerTlsEventKind::TlsChannelStarted ||
        value.kind == PlayerTlsEventKind::TlsInfo ||
        value.kind == PlayerTlsEventKind::TlsMessage ||
        value.kind == PlayerTlsEventKind::TlsKeyLog ||
        value.kind == PlayerTlsEventKind::TlsHandshakeComplete ||
        value.kind == PlayerTlsEventKind::TlsHandshakeFailed;
    if (channel != (value.peer_role < value.player_count &&
                    value.peer_role != value.local_role &&
                    value.lane < 2 &&
                    value.client == (value.peer_role < value.local_role)) ||
        (!channel && (value.peer_role != NO_TLS_PEER ||
                      value.lane != NO_TLS_LANE)))
        throw std::runtime_error("invalid-P1-TLS-channel-identity");

    const auto nonempty = [&](std::size_t index) {
        return !value.payloads.at(index).empty();
    };
    switch (value.kind) {
    case PlayerTlsEventKind::TlsContextLoaded:
        if (!nonempty(0) || !nonempty(1) || nonempty(2) || nonempty(3) ||
            nonempty(4) || nonempty(5))
            throw std::runtime_error("invalid-P1-TLS-context-material");
        break;
    case PlayerTlsEventKind::TlsMessage:
    case PlayerTlsEventKind::TlsKeyLog:
        if (!nonempty(0) || nonempty(1) || nonempty(2) || nonempty(3) ||
            nonempty(4) || nonempty(5))
            throw std::runtime_error("invalid-P1-TLS-callback-payload");
        break;
    case PlayerTlsEventKind::TlsHandshakeComplete:
        if (!nonempty(0) || !nonempty(1) || !nonempty(2) ||
            !nonempty(4) || !nonempty(5) ||
            value.protocol_name.empty() || value.cipher_name.empty())
            throw std::runtime_error("invalid-P1-TLS-terminal-state");
        break;
    case PlayerTlsEventKind::TlsHandshakeFailed:
        if (!player_tls_detail::empty_payloads(value) ||
            value.failure_class.empty())
            throw std::runtime_error("invalid-P1-TLS-failure-state");
        break;
    default:
        if (!player_tls_detail::empty_payloads(value))
            throw std::runtime_error("unexpected-P1-TLS-payload");
        break;
    }

    static constexpr std::string_view domain =
        "KPI_P1_PLAYER_TLS_STATE_PREFIX_V1\n";
    std::size_t reserve = domain.size() + 25 * 8;
    const auto add_size = [&](std::size_t size) {
        if (size > std::numeric_limits<std::size_t>::max() - reserve)
            throw std::runtime_error("P1-player-TLS-state-size-overflow");
        reserve += size;
    };
    for (const auto value : {
             value.player_id, value.parent_player_id, value.protocol_name,
             value.cipher_name, value.failure_class})
        add_size(value.size());
    for (const auto payload : value.payloads) add_size(payload.size());
    std::vector<unsigned char> output;
    output.reserve(reserve);
    output.insert(output.end(), domain.begin(), domain.end());
    for (const auto field : {
             static_cast<std::uint64_t>(kind), value.local_role,
             value.player_count, value.peer_role, value.lane, value.client,
             value.write_direction, value.protocol_version,
             value.content_type, value.info_where, value.info_return,
             value.verify_result, value.ssl_state, value.shutdown_state})
        player_tls_detail::append_u64(output, field);
    player_tls_detail::append_string(output, value.player_id);
    player_tls_detail::append_string(output, value.parent_player_id);
    player_tls_detail::append_string(output, value.protocol_name);
    player_tls_detail::append_string(output, value.cipher_name);
    player_tls_detail::append_string(output, value.failure_class);
    for (const auto payload : value.payloads)
        player_tls_detail::append_bytes(output, payload);
    return output;
}

// CryptoPlayer and ssl_socket call this no-throw interface. False means the
// exact event was not retained; the caller must abort and the capsule stays
// unavailable. It cannot be used to mint or close a capsule.
class PlayerTlsStateHook {
public:
    virtual ~PlayerTlsStateHook() = default;
    virtual bool record_player_tls_event(
        const PlayerTlsEventView&) noexcept = 0;
    virtual void player_tls_unavailable_noexcept() noexcept = 0;
};

struct PlayerTlsStateHookSourceStatus final {
    bool canonical_raw_event_encoding{};
    bool actual_certificate_and_private_key_der{};
    bool openssl_message_info_keylog_callbacks{};
    bool handshake_session_material{};
    bool openssl_drbg_internal_state{};
    bool openssl_record_layer_internal_state{};
    bool deterministic_replay_verified{};
    bool complete_tls_process_view{};
    bool configured{};
};

inline constexpr PlayerTlsStateHookSourceStatus
kPlayerTlsStateHookSourceStatus{
    .canonical_raw_event_encoding = true,
    .actual_certificate_and_private_key_der = false,
    .openssl_message_info_keylog_callbacks = false,
    .handshake_session_material = false,
    .openssl_drbg_internal_state = false,
    .openssl_record_layer_internal_state = false,
    .deterministic_replay_verified = false,
    .complete_tls_process_view = false,
    .configured = false,
};

} // namespace kpi::mpc::p1_private_state

namespace kpb::measurement::p1_state_capsule {

// Complete before friendship so an exact-name lookalike cannot acquire the
// recorder's private Ledger. Only P1CorruptStateRecorderAuthority constructs
// this shared-ledger adapter.
class P1PlayerTlsStateAdapter final
    : public kpi::mpc::p1_private_state::PlayerTlsStateHook {
    struct Storage;
    std::unique_ptr<Storage> storage_;
    explicit P1PlayerTlsStateAdapter(std::unique_ptr<Storage>);
    friend class P1PlayerTlsStateAdapterFactoryBridge;

public:
    P1PlayerTlsStateAdapter(const P1PlayerTlsStateAdapter&) = delete;
    P1PlayerTlsStateAdapter& operator=(
        const P1PlayerTlsStateAdapter&) = delete;
    P1PlayerTlsStateAdapter(P1PlayerTlsStateAdapter&&) = delete;
    P1PlayerTlsStateAdapter& operator=(P1PlayerTlsStateAdapter&&) = delete;
    ~P1PlayerTlsStateAdapter() override;

    bool record_player_tls_event(
        const kpi::mpc::p1_private_state::PlayerTlsEventView&) noexcept
        override;
    void player_tls_unavailable_noexcept() noexcept override;
};

} // namespace kpb::measurement::p1_state_capsule
