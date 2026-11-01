#pragma once

#include "auth_groups.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace kpi::mpc::p1_capture {

class P1CaptureStream;
class P1CapturingPlayer;

// Complete before P1CaptureStream and P1CapturingPlayer grant friendship.
// Keeping this declaration in a neutral contract prevents a direct-include
// translation unit from defining the exact friend name and gaining access to
// either object's private capture state.
class P1OwnerInputOffsetFrameSink {
public:
    virtual ~P1OwnerInputOffsetFrameSink() = default;
    virtual void owner_input_preprocessing_share_frame(
        unsigned owner, std::span<const unsigned char> exact_frame) = 0;
    virtual void owner_input_offset_frame(
        unsigned owner, std::span<const unsigned char> exact_frame) = 0;
};

// Typed serialization boundary for P1-local authenticated state. It can only
// be derived from an already role-locked P1CapturingPlayer capability; there
// is no fd or raw-stream production factory.
class P1TypedCaptureSeams final : public P1OwnerInputOffsetFrameSink {
    class FinalGroupOpeningPermit final {
        P1TypedCaptureSeams* owner_;
        MascotContext* context_;
        std::uint64_t generation_;
        std::uint64_t failure_epoch_;
        std::vector<unsigned char> g1_state_;
        std::vector<unsigned char> g2_state_;
        bool active_;

        FinalGroupOpeningPermit(
            P1TypedCaptureSeams&, MascotContext&, std::vector<unsigned char>,
            std::vector<unsigned char>);
        friend class P1TypedCaptureSeams;
    public:
        ~FinalGroupOpeningPermit();
        FinalGroupOpeningPermit(FinalGroupOpeningPermit&&) noexcept;
        FinalGroupOpeningPermit(const FinalGroupOpeningPermit&) = delete;
        FinalGroupOpeningPermit& operator=(
            const FinalGroupOpeningPermit&) = delete;
        FinalGroupOpeningPermit& operator=(
            FinalGroupOpeningPermit&&) = delete;
    };

    P1CaptureStream& capture_;
    P1CapturingPlayer& player_;
    std::vector<unsigned char> released_projection_;

    P1CapturingPlayer& bound_player() const { return player_; }
    void released_projection(std::span<const unsigned char> projection10685);
    void close_complete();
    void poison() noexcept;
    void bind_financial_query_model(
        const std::string& model_sha256,
        const std::string& query_store_sha256);
    FinalGroupOpeningPermit begin_final_group_opening_capture(
        MascotContext&, std::span<const AuthG1, 2>, const AuthG2&);
    void final_group_openings(
        FinalGroupOpeningPermit&&, MascotContext&,
        std::span<const AuthG1, 2>, const AuthG2&,
        std::span<const G1Value, 2>, const G2Value&);
    friend class ::kpi::mpc::MascotContext;
    friend class ::kpi::mpc::GroupMacSetup;
    friend class ::kpi::mpc::financial::FinancialValidatedAssignment;

public:
    explicit P1TypedCaptureSeams(P1CapturingPlayer& player);

    void owner_input_preprocessing_share_frame(
        unsigned owner,
        std::span<const unsigned char> exact_frame) override;
    void owner_input_offset_frame(
        unsigned owner,
        std::span<const unsigned char> exact_frame) override;
    void authenticated_values(
        ScalarCaptureSite, std::span<const AuthScalar> values);
    void randomness_values(
        ScalarCaptureSite, std::span<const AuthScalar> values);
    void mac_key_share(const Fr& value);
    void field_openings(std::span<const Fr> values);
    void masked_field_differences(std::span<const Fr> values);
    void masked_group_differences(std::span<const G1Value> values);
    void proof_base_group_state(
        std::span<const AuthG1, 4> values, const AuthG2& b2);
    void beaver_mixed_group_state(std::span<const AuthG1, 6> values);
    void beaver_product_group_state(std::span<const AuthG1, 2> values);
#ifdef KPI_P1_CAPTURE_TEST_SETUP
    void test_only_released_projection(
        std::span<const unsigned char> projection10685) {
        released_projection(projection10685);
    }
    void test_only_close_complete() { close_complete(); }
    void test_only_bind_query_model(
        const std::string& model_sha256,
        const std::string& query_store_sha256) {
        bind_financial_query_model(model_sha256, query_store_sha256);
    }
    void test_only_final_group_state_and_openings(
        std::span<const AuthG1, 2>, const AuthG2&,
        std::span<const G1Value, 2>, std::span<const G2Value, 1>);
#endif
};

} // namespace kpi::mpc::p1_capture
