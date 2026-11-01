#include "../../p1_capture_stream.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {
using namespace kpi::mpc::p1_capture;

std::string repeated(char value) { return std::string(64, value); }

RunBinding binding() {
    return {
        .attempt_id = "33333333-3333-4333-8333-333333333333",
        .cohort_sha256 = repeated('3'),
        .financial_run_id = repeated('4'),
        .capture_identity = "22222222-2222-4222-8222-222222222222",
        .protocol_source_sha256 = repeated('5'),
        .protocol_build_sha256 = repeated('6'),
        .protocol_launch_sha256 = repeated('7'),
        .model_preimage_sha256 = repeated('8'),
        .query_store_preimage_sha256 = repeated('9'),
        .scalar_capture_manifest_sha256 =
            std::string(SCALAR_CAPTURE_MANIFEST_SHA256),
    };
}

std::array<unsigned char, 32> field(unsigned char value) {
    std::array<unsigned char, 32> result{};
    result[0] = value;
    return result;
}

void instrument_all(P1CaptureStream& stream) {
    for (unsigned encoded = 1; encoded <= 17; ++encoded)
        stream.declare_instrumented(static_cast<Semantic>(encoded));
}

int complete(bool large_transport, bool omit_scalar_site = false,
             bool omit_mac_key = false, bool wrong_final_a = false,
             bool wrong_group_stage = false, bool wrong_final_a_mac = false,
             bool wrong_final_b2_mac = false) {
    if (::dup2(STDOUT_FILENO, 23) != 23) return 1;
    auto stream = P1CaptureStream::test_only_begin(23, 1, 1, true, binding());
    instrument_all(*stream);
    const auto key = field(0x30);
    if (!omit_mac_key)
        stream->mac_key_share(Fr32Lane::checked(key));
    for (unsigned owner = 0; owner < 3; ++owner) {
        const auto value = field(static_cast<unsigned char>(owner + 1));
        std::array<unsigned char, 5 * 32> preprocessing{};
        preprocessing.fill(static_cast<unsigned char>(owner + 11));
        stream->owner_input_preprocessing_share_frame(
            owner, Fr32Lane::checked(preprocessing));
        stream->owner_input_offset_frame(owner, Fr32Lane::checked(value));
    }
    const std::array<unsigned char, 3> sent{{0x10, 0x11, 0x12}};
    const std::array<unsigned char, 2> received{{0x20, 0x21}};
    stream->peer_transport(Direction::Send, 2, stream->root_fork(), sent);
    stream->peer_transport(Direction::Receive, 0, stream->root_fork(), received);
    if (large_transport) {
        std::vector<unsigned char> large(3 * (1U << 20) + 17, 0xa7);
        stream->peer_transport(
            Direction::Send, 2, stream->root_fork(), large);
    }
    const auto share = field(0x31), mac = field(0x32);
    for (unsigned encoded = 1; encoded <= 22; ++encoded) {
        if (omit_scalar_site && encoded == 19) continue;
        const auto site = static_cast<ScalarCaptureSite>(encoded);
        if (scalar_capture_kind(site) == ScalarCaptureKind::Randomness)
            stream->randomness(
                site, Fr32Lane::checked(share), Fr32Lane::checked(mac));
        else
            stream->authenticated_values(
                site, Fr32Lane::checked(share), Fr32Lane::checked(mac));
    }
    stream->field_opening(Fr32Lane::checked(share));
    std::array<unsigned char, 4 * AUTH_G1_CAPTURE_BYTES> base_g1{};
    base_g1.fill(0x41);
    std::array<unsigned char, AUTH_G2_CAPTURE_BYTES> base_g2{};
    base_g2.fill(0x42);
    stream->authenticated_g1_state(
        GroupStateStage::Base, AuthenticatedG1Lane::checked(base_g1));
    stream->authenticated_g2_state(
        GroupStateStage::Base, AuthenticatedG2Lane::checked(base_g2));
    std::array<unsigned char, 6 * AUTH_G1_CAPTURE_BYTES> mixed_g1{};
    mixed_g1.fill(0x43);
    stream->authenticated_g1_state(
        wrong_group_stage ? GroupStateStage::Products : GroupStateStage::Mixed,
        AuthenticatedG1Lane::checked(mixed_g1));
    std::array<unsigned char, 2 * G1_CAPTURE_BYTES> g1{}; g1.fill(0x44);
    std::array<unsigned char, G2_CAPTURE_BYTES> g2{}; g2.fill(0x42);
    std::array<unsigned char, 2 * 32> masked_fields{};
    masked_fields.fill(0x45);
    stream->masked_field_differences(Fr32Lane::checked(masked_fields));
    stream->masked_group_differences(G1Lane::checked(g1));
    std::array<unsigned char, 2 * AUTH_G1_CAPTURE_BYTES> products_g1{};
    products_g1.fill(0x46);
    stream->authenticated_g1_state(
        GroupStateStage::Products,
        AuthenticatedG1Lane::checked(products_g1));
    std::array<unsigned char, 2 * AUTH_G1_CAPTURE_BYTES> final_g1{};
    std::copy_n(base_g1.begin(), AUTH_G1_CAPTURE_BYTES, final_g1.begin());
    std::fill(final_g1.begin() + AUTH_G1_CAPTURE_BYTES, final_g1.end(), 0x47);
    if (wrong_final_a) final_g1[0] ^= 1;
    if (wrong_final_a_mac) final_g1[G1_CAPTURE_BYTES] ^= 1;
    stream->authenticated_g1_state(
        GroupStateStage::Final, AuthenticatedG1Lane::checked(final_g1));
    auto final_g2 = base_g2;
    if (wrong_final_b2_mac) final_g2[G2_CAPTURE_BYTES] ^= 1;
    stream->authenticated_g2_state(
        GroupStateStage::Final, AuthenticatedG2Lane::checked(final_g2));
    stream->final_group_opening(G1Lane::checked(g1));
    stream->final_group_opening(G2Lane::checked(g2));
    stream->bind_query_model_preimages(repeated('8'), repeated('9'));
    std::vector<unsigned char> projection(10685);
    for (std::size_t i = 0; i < projection.size(); ++i)
        projection[i] = static_cast<unsigned char>(i % 251);
    stream->seal_projection(projection);
    stream->close_complete();
    return 0;
}

int delayed_reader_is_lossless() {
    int pipe_fds[2];
    if (::pipe(pipe_fds) != 0) return 1;
    if (::dup2(pipe_fds[1], 23) != 23) return 2;
    ::close(pipe_fds[1]);
    std::size_t drained = 0;
    std::thread reader([&] {
        ::usleep(100000);
        std::array<unsigned char, 8192> buffer{};
        for (;;) {
            const auto count = ::read(pipe_fds[0], buffer.data(), buffer.size());
            if (count == 0) break;
            if (count < 0) return;
            drained += static_cast<std::size_t>(count);
        }
    });
    {
        auto stream = P1CaptureStream::test_only_begin(
            23, 1, 1, true, binding());
        stream->declare_instrumented(Semantic::PeerTransport);
        std::vector<unsigned char> blocked(3 * (1U << 20), 0x6b);
        stream->peer_transport(
            Direction::Send, 2, stream->root_fork(), blocked);
    }
    reader.join();
    ::close(pipe_fds[0]);
    return drained > 3 * (1U << 20) ? 0 : 3;
}

int closed_consumer_poison() {
    int pipe_fds[2];
    if (::pipe(pipe_fds) != 0) return 1;
    if (::dup2(pipe_fds[1], 23) != 23) return 2;
    ::close(pipe_fds[1]);
    auto stream = P1CaptureStream::test_only_begin(
        23, 1, 1, true, binding());
    stream->declare_instrumented(Semantic::PeerTransport);
    ::close(pipe_fds[0]);
    const std::array<unsigned char, 1> body{{0x6b}};
    try {
        stream->peer_transport(
            Direction::Send, 2, stream->root_fork(), body);
    } catch (const CaptureRefused&) {
        try {
            stream->peer_transport(
                Direction::Send, 2, stream->root_fork(), body);
        } catch (const CaptureRefused&) {
            return 0;
        }
    }
    return 3;
}

int role_bypass_refusal() {
    if (::dup2(STDOUT_FILENO, 23) != 23) return 1;
    try {
        (void)P1CaptureStream::test_only_begin(23, 1, 0, true, binding());
    } catch (const CaptureRefused&) {
        return 0;
    }
    return 2;
}
}

int main(int argc, char** argv) {
    try {
        if (argc == 1) return complete(false);
        if (argc != 2) return 64;
        const std::string scenario(argv[1]);
        if (scenario == "large") return complete(true);
        if (scenario == "missing-scalar-site") return complete(false, true);
        if (scenario == "missing-mac-key")
            return complete(false, false, true);
        if (scenario == "wrong-final-a")
            return complete(false, false, false, true);
        if (scenario == "wrong-group-stage")
            return complete(false, false, false, false, true);
        if (scenario == "wrong-final-a-mac")
            return complete(false, false, false, false, false, true);
        if (scenario == "wrong-final-b2-mac")
            return complete(false, false, false, false, false, false, true);
        if (scenario == "delayed-reader") return delayed_reader_is_lossless();
        if (scenario == "closed-consumer") return closed_consumer_poison();
        if (scenario == "role-bypass") return role_bypass_refusal();
        return 64;
    }
    catch (...) { return 78; }
}
