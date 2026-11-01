#pragma once

#include "p1_capture_types.hpp"
#include "p1_capture_seams_contract.hpp"
#include "p1_capturing_player_contract.hpp"
#include "p1_scalar_capture_manifest.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <utility>

namespace kpi::mpc::p1_capture {

inline constexpr unsigned P1_CAPTURE_CONFIGURED = 0;
inline constexpr std::size_t MAX_CHUNK_BYTES = 1U << 16;
inline constexpr std::size_t G1_CAPTURE_BYTES = 65;
inline constexpr std::size_t G2_CAPTURE_BYTES = 129;
inline constexpr std::size_t AUTH_G1_CAPTURE_BYTES = 2 * G1_CAPTURE_BYTES;
inline constexpr std::size_t AUTH_G2_CAPTURE_BYTES = 2 * G2_CAPTURE_BYTES;

enum class Direction : std::uint8_t {
    Send = 1,
    Receive = 2,
    Local = 3,
};

enum class Semantic : std::uint8_t {
    OwnerInputOffsetFrame = 1,
    PeerTransport = 2,
    AuthenticatedShare = 3,
    MacShare = 4,
    RandomnessShare = 5,
    RandomnessMac = 6,
    GroupOpeningG1 = 7,
    GroupOpeningG2 = 8,
    PublicProjection = 9,
    FieldOpening = 10,
    OwnerInputPreprocessingShareFrame = 11,
    MaskedGroupDifferenceG1 = 12,
    MaskedFieldDifference = 13,
    MacKeyShare = 14,
    AuthenticatedG1State = 15,
    AuthenticatedG2State = 16,
    ScalarCaptureBinding = 17,
};

enum class GroupStateStage : std::uint8_t {
    Base = 1,
    Mixed = 2,
    Products = 3,
    Final = 4,
};

class Fr32Lane final {
    std::span<const unsigned char> bytes_;
    explicit Fr32Lane(std::span<const unsigned char> value) : bytes_(value) {}
public:
    static Fr32Lane checked(std::span<const unsigned char>);
    std::span<const unsigned char> bytes() const { return bytes_; }
    std::size_t elements() const { return bytes_.size() / 32; }
};

class G1Lane final {
    std::span<const unsigned char> bytes_;
    explicit G1Lane(std::span<const unsigned char> value) : bytes_(value) {}
public:
    static G1Lane checked(std::span<const unsigned char>);
    std::span<const unsigned char> bytes() const { return bytes_; }
};

class G2Lane final {
    std::span<const unsigned char> bytes_;
    explicit G2Lane(std::span<const unsigned char> value) : bytes_(value) {}
public:
    static G2Lane checked(std::span<const unsigned char>);
    std::span<const unsigned char> bytes() const { return bytes_; }
};

class AuthenticatedG1Lane final {
    std::span<const unsigned char> bytes_;
    explicit AuthenticatedG1Lane(std::span<const unsigned char> value)
        : bytes_(value) {}
public:
    static AuthenticatedG1Lane checked(std::span<const unsigned char>);
    std::span<const unsigned char> bytes() const { return bytes_; }
};

class AuthenticatedG2Lane final {
    std::span<const unsigned char> bytes_;
    explicit AuthenticatedG2Lane(std::span<const unsigned char> value)
        : bytes_(value) {}
public:
    static AuthenticatedG2Lane checked(std::span<const unsigned char>);
    std::span<const unsigned char> bytes() const { return bytes_; }
};

class CaptureRefused final : public std::exception {
public:
    const char* what() const noexcept override;
};

class P1CaptureStream final {
    class Impl;
    class TransportRecorder final {
        P1CaptureStream& owner_;
        explicit TransportRecorder(P1CaptureStream& owner) : owner_(owner) {}
        void record(Direction, unsigned peer, const ForkId&,
                    std::span<const unsigned char>);
        friend class P1CaptureStream;
        friend class P1CapturingPlayer;
    };
    std::unique_ptr<Impl> impl_;
    P1CaptureStream(int fixed_fd, unsigned round, unsigned authenticated_role,
                    bool encrypted_transport, RunBinding);
    void transport_transaction(
        const std::function<void()>& operation,
        const std::function<void(TransportRecorder&)>& record);
    void begin_async_receive(const std::function<void()>& operation);
    void finish_async_receive(
        const std::function<void()>& operation,
        const std::function<void(TransportRecorder&)>& record);
    void poison() noexcept;
    friend class P1CapturingPlayer;
    friend class P1TypedCaptureSeams;

public:
    ~P1CaptureStream();
    P1CaptureStream(const P1CaptureStream&) = delete;
    P1CaptureStream& operator=(const P1CaptureStream&) = delete;
    P1CaptureStream(P1CaptureStream&&) = delete;
    P1CaptureStream& operator=(P1CaptureStream&&) = delete;

    const ForkId& root_fork() const;
    void declare_instrumented(Semantic);
    ForkId register_fork(const ForkId& parent, const std::string& suffix);
    void peer_transport(Direction, unsigned peer, const ForkId&,
                        std::span<const unsigned char>);
    void owner_input_preprocessing_share_frame(unsigned owner, Fr32Lane);
    void owner_input_offset_frame(unsigned owner, Fr32Lane);
    void authenticated_values(
        ScalarCaptureSite, Fr32Lane shares, Fr32Lane macs);
    void randomness(
        ScalarCaptureSite, Fr32Lane shares, Fr32Lane macs);
    void mac_key_share(Fr32Lane);
    void field_opening(Fr32Lane);
    void masked_field_differences(Fr32Lane);
    void masked_group_differences(G1Lane);
    void authenticated_g1_state(GroupStateStage, AuthenticatedG1Lane);
    void authenticated_g2_state(GroupStateStage, AuthenticatedG2Lane);
    void final_group_opening(G1Lane);
    void final_group_opening(G2Lane);
    void bind_query_model_preimages(
        const std::string& model_sha256,
        const std::string& query_store_sha256);
    void seal_projection(std::span<const unsigned char> projection10685);
    void close_complete();

#ifdef KPI_P1_CAPTURE_TEST_SETUP
    static std::shared_ptr<P1CaptureStream> test_only_begin(
        int fixed_fd, unsigned round, unsigned authenticated_role,
        bool encrypted_transport, RunBinding binding) {
        return std::shared_ptr<P1CaptureStream>(new P1CaptureStream(
            fixed_fd, round, authenticated_role, encrypted_transport,
            std::move(binding)));
    }
#endif
};

struct SourceStatus {
    std::string schema;
    bool configured;
    bool registered_driver_integrated;
    bool producer_integrated;
    bool launch_authorized;
    bool actual_receipt_enabled;
};

SourceStatus source_status();

} // namespace kpi::mpc::p1_capture
