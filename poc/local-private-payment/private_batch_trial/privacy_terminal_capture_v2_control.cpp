#include "privacy_terminal_capture_v2.hpp"
#include "native_terminal_mapping_source.hpp"
#include "native_terminal_projection_test_fixture.hpp"

#include <array>
#include <openssl/sha.h>
#include <string>
#include <type_traits>
#include <utility>
#include <unistd.h>

namespace {
using namespace kpb::capture;

template<class T>
concept HasUntypedClose = requires(T& value) { value.close_complete(); };
static_assert(!HasUntypedClose<TerminalCaptureV2>);
static_assert(!std::is_default_constructible_v<ResolvedSettlementV2>);
static_assert(!std::is_default_constructible_v<PreNetworkTerminalClosedV2>);

std::string repeated(const std::string& pair) {
    std::string result;
    for (unsigned index = 0; index < 32; ++index) result += pair;
    return result;
}
Binding binding(const std::string& projection_sha256) {
    return {
        "33333333-3333-4333-8333-333333333333",
        repeated("31"), repeated("15"),
        "22222222-2222-4222-8222-222222222222", projection_sha256,
        1, repeated("16"), repeated("17"),
    };
}

void alias_stdout(int target) {
    if (::dup2(STDOUT_FILENO, target) != target) throw CaptureRefused();
}

void apply_mapping(TerminalCaptureV2& hook, const DurableFinalV2& final,
                   std::span<const std::byte> projection,
                   const Binding& selected, unsigned char origin_salt = 0) {
    auto source = origin_salt == 0
        ? kpb::native_terminal::NativeTerminalMappingSourceAuthority::
            test_only_candidate_from_projection(projection, 1, selected)
        : kpb::native_terminal::NativeTerminalMappingSourceAuthority::
            test_only_candidate_from_projection_with_origin_salt(
                projection, 1, selected, origin_salt);
    hook.after_complete_mapping_source(final, std::move(source));
}

void acknowledged(TerminalCaptureV2& hook,
                  std::span<const std::byte> projection,
                  const Binding& selected) {
    auto candidate = hook.after_candidate_constructed(
        10, repeated("44"), repeated("45"));
    auto r0 = hook.after_r0_verified(
        std::move(candidate), 11, repeated("46"),
        selected.projection_sha256);
    auto native = hook.after_native_full_verified(
        std::move(r0), 12, repeated("47"), repeated("45"),
        selected.projection_sha256);
    auto final = hook.after_durable_final(
        std::move(native), 13, repeated("48"));
    apply_mapping(hook, final, projection, selected);
    auto attempted = hook.after_testnet_submit_attempted(
        std::move(final), 14, repeated("49"));
    auto submitted = hook.after_testnet_submit_acknowledged(
        std::move(attempted), 15, repeated("49"));
    auto accepted = hook.after_accepted_case(
        std::move(submitted), 16, repeated("45"), repeated("49"),
        repeated("4a"));
    auto settled = hook.after_durable_settlement_resolved(
        std::move(accepted), 17, repeated("4b"));
    hook.after_trial_closed(std::move(settled), 18);
}

DurableFinalV2 ready_for_submit(TerminalCaptureV2& hook,
                                std::span<const std::byte> projection,
                                const Binding& selected,
                                unsigned char origin_salt = 0) {
    auto candidate = hook.after_candidate_constructed(
        10, repeated("44"), repeated("45"));
    auto r0 = hook.after_r0_verified(
        std::move(candidate), 11, repeated("46"),
        selected.projection_sha256);
    auto native = hook.after_native_full_verified(
        std::move(r0), 12, repeated("47"), repeated("45"),
        selected.projection_sha256);
    auto final = hook.after_durable_final(
        std::move(native), 13, repeated("48"));
    apply_mapping(hook, final, projection, selected, origin_salt);
    return final;
}

int run(const std::string& scenario) {
    alias_stdout(21);
    auto projection =
        kpb::native_terminal::projection_test_fixture::make(1);
    if (scenario == "group-id-row-changed")
        projection[193 + 692] ^= std::byte{1};
    const auto selected = binding(
        kpb::native_terminal::projection_test_fixture::hex(
            kpb::native_terminal::projection_test_fixture::identity(
                projection)));
    TerminalCaptureV2Hook<21, 1> fixed(selected);
    if (scenario == "group-id-origin-1" ||
        scenario == "group-id-origin-2" ||
        scenario == "group-id-row-changed") {
        const unsigned char salt =
            scenario == "group-id-origin-2" ? 2 : 1;
        auto final = ready_for_submit(
            fixed.channel(), projection, selected, salt);
        auto closed = fixed.channel().after_pre_network_capture_closed(
            std::move(final), 14);
        closed.test_only_consume();
        return 0;
    }
    if (scenario == "acknowledged") {
        acknowledged(fixed.channel(), projection, selected); return 0;
    }
    if (scenario == "pre-network-close") {
        auto final = ready_for_submit(
            fixed.channel(), projection, selected);
        auto closed = fixed.channel().after_pre_network_capture_closed(
            std::move(final), 14);
        closed.test_only_consume();
        return 0;
    }
    if (scenario == "pre-network-replay") {
        auto final = ready_for_submit(
            fixed.channel(), projection, selected);
        auto closed = fixed.channel().after_pre_network_capture_closed(
            std::move(final), 14);
        closed.test_only_consume();
        closed.test_only_consume();
        return 0;
    }
    if (scenario == "pre-network-no-mapping") {
        auto candidate = fixed.channel().after_candidate_constructed(
            10, repeated("44"), repeated("45"));
        auto r0 = fixed.channel().after_r0_verified(
            std::move(candidate), 11, repeated("46"),
            selected.projection_sha256);
        auto native = fixed.channel().after_native_full_verified(
            std::move(r0), 12, repeated("47"), repeated("45"),
            selected.projection_sha256);
        auto final = fixed.channel().after_durable_final(
            std::move(native), 13, repeated("48"));
        (void)fixed.channel().after_pre_network_capture_closed(
            std::move(final), 14);
        return 0;
    }
    if (scenario == "mapping-replay") {
        auto candidate = fixed.channel().after_candidate_constructed(
            10, repeated("44"), repeated("45"));
        auto r0 = fixed.channel().after_r0_verified(
            std::move(candidate), 11, repeated("46"),
            selected.projection_sha256);
        auto native = fixed.channel().after_native_full_verified(
            std::move(r0), 12, repeated("47"), repeated("45"),
            selected.projection_sha256);
        auto final = fixed.channel().after_durable_final(
            std::move(native), 13, repeated("48"));
        auto source =
            kpb::native_terminal::NativeTerminalMappingSourceAuthority::
                test_only_candidate_from_projection(
                    projection, 1, selected);
        fixed.channel().after_complete_mapping_source(
            final, std::move(source));
        fixed.channel().after_complete_mapping_source(
            final, std::move(source));
        return 0;
    }
    if (scenario == "mapping-wrong-body") {
        auto changed = projection;
        changed[193 + 404] ^= std::byte{1};
        (void)kpb::native_terminal::NativeTerminalMappingSourceAuthority::
            test_only_candidate_from_projection(changed, 1, selected);
        return 0;
    }
    if (scenario == "mapping-empty-commitment") {
        auto changed = projection;
        static constexpr std::array<unsigned char, 8> domain{
            'K', 'P', 'X', '1', 'C', 'M', 'E', 0};
        std::array<unsigned char, 32> empty{};
        if (SHA256(domain.data(), domain.size(), empty.data()) == nullptr)
            throw CaptureRefused();
        for (unsigned index = 0; index < empty.size(); ++index)
            changed[193 + 692 + index] =
                static_cast<std::byte>(empty[index]);
        auto changed_binding = binding(
            kpb::native_terminal::projection_test_fixture::hex(
                kpb::native_terminal::projection_test_fixture::identity(
                    changed)));
        (void)kpb::native_terminal::NativeTerminalMappingSourceAuthority::
            test_only_candidate_from_projection(
                changed, 1, changed_binding);
        return 0;
    }
    if (scenario == "mapping-wrong-plan") {
        auto changed = selected;
        changed.capture_plan_sha256 = repeated("18");
        auto source =
            kpb::native_terminal::NativeTerminalMappingSourceAuthority::
                test_only_candidate_from_projection(
                    projection, 1, changed);
        auto candidate = fixed.channel().after_candidate_constructed(
            10, repeated("44"), repeated("45"));
        auto r0 = fixed.channel().after_r0_verified(
            std::move(candidate), 11, repeated("46"),
            selected.projection_sha256);
        auto native = fixed.channel().after_native_full_verified(
            std::move(r0), 12, repeated("47"), repeated("45"),
            selected.projection_sha256);
        auto final = fixed.channel().after_durable_final(
            std::move(native), 13, repeated("48"));
        fixed.channel().after_complete_mapping_source(
            final, std::move(source));
        return 0;
    }
    if (scenario == "mapping-wrong-construction-attempt") {
        auto changed = selected;
        changed.construction_attempt_sha256 = repeated("19");
        auto source =
            kpb::native_terminal::NativeTerminalMappingSourceAuthority::
                test_only_candidate_from_projection(
                    projection, 1, changed);
        auto candidate = fixed.channel().after_candidate_constructed(
            10, repeated("44"), repeated("45"));
        auto r0 = fixed.channel().after_r0_verified(
            std::move(candidate), 11, repeated("46"),
            selected.projection_sha256);
        auto native = fixed.channel().after_native_full_verified(
            std::move(r0), 12, repeated("47"), repeated("45"),
            selected.projection_sha256);
        auto final = fixed.channel().after_durable_final(
            std::move(native), 13, repeated("48"));
        fixed.channel().after_complete_mapping_source(
            final, std::move(source));
        return 0;
    }
    if (scenario == "mapping-candidate-covert-owner") {
        std::array<std::array<unsigned char, 32>, 3> nfs{};
        std::array<std::array<std::array<unsigned char, 32>, 2>, 3>
            tuples{};
        for (unsigned owner = 0; owner < 3; ++owner) {
            nfs[owner] =
                kpb::native_terminal::projection_test_fixture::digest(
                    0xd0 + owner);
            for (unsigned index = 0; index < 2; ++index)
                tuples[owner][index] =
                    kpb::native_terminal::projection_test_fixture::digest(
                        0xe0 + owner * 2 + index);
        }
        (void)kpb::native_terminal::NativeTerminalMappingSourceAuthority::
            test_only_candidate_with_owner_rows(
                projection, 1, selected, nfs, tuples);
        return 0;
    }
    if (scenario == "mapping-baseline-zero-owner" ||
        scenario == "mapping-baseline-duplicate-owner") {
        auto baseline = selected;
        baseline.construction_classification = 2;
        std::array<std::array<unsigned char, 32>, 3> nfs{};
        std::array<std::array<std::array<unsigned char, 32>, 2>, 3>
            tuples{};
        if (scenario == "mapping-baseline-duplicate-owner") {
            for (auto& nf : nfs)
                nf = kpb::native_terminal::projection_test_fixture::digest(
                    0xd0);
            for (auto& owner : tuples)
                for (auto& tuple : owner)
                    tuple =
                        kpb::native_terminal::projection_test_fixture::digest(
                            0xe0);
        }
        (void)kpb::native_terminal::NativeTerminalMappingSourceAuthority::
            test_only_baseline_from_projection(
                projection, 1, baseline, nfs, tuples);
        return 0;
    }
    if (scenario == "wrong-projection") {
        auto candidate = fixed.channel().after_candidate_constructed(
            10, repeated("44"), repeated("45"));
        (void)fixed.channel().after_r0_verified(
            std::move(candidate), 11, repeated("46"), repeated("13"));
        return 0;
    }
    if (scenario == "wrong-case") {
        auto candidate = fixed.channel().after_candidate_constructed(
            10, repeated("44"), repeated("45"));
        auto r0 = fixed.channel().after_r0_verified(
            std::move(candidate), 11, repeated("46"),
            selected.projection_sha256);
        (void)fixed.channel().after_native_full_verified(
            std::move(r0), 12, repeated("47"), repeated("4f"),
            selected.projection_sha256);
        return 0;
    }
    if (scenario == "r0-replayed") {
        auto candidate = fixed.channel().after_candidate_constructed(
            10, repeated("44"), repeated("45"));
        auto r0 = fixed.channel().after_r0_verified(
            std::move(candidate), 11, repeated("46"),
            selected.projection_sha256);
        (void)r0;
        (void)fixed.channel().after_r0_verified(
            std::move(candidate), 12, repeated("46"),
            selected.projection_sha256);
        return 0;
    }
    if (scenario == "native-full-replayed") {
        auto candidate = fixed.channel().after_candidate_constructed(
            10, repeated("44"), repeated("45"));
        auto r0 = fixed.channel().after_r0_verified(
            std::move(candidate), 11, repeated("46"),
            selected.projection_sha256);
        auto native = fixed.channel().after_native_full_verified(
            std::move(r0), 12, repeated("47"), repeated("45"),
            selected.projection_sha256);
        (void)native;
        (void)fixed.channel().after_native_full_verified(
            std::move(r0), 13, repeated("47"), repeated("45"),
            selected.projection_sha256);
        return 0;
    }
    if (scenario == "duplicate-submit") {
        auto final = ready_for_submit(
            fixed.channel(), projection, selected);
        auto attempted = fixed.channel().after_testnet_submit_attempted(
            std::move(final), 14, repeated("49"));
        (void)attempted;
        (void)fixed.channel().after_testnet_submit_attempted(
            std::move(final), 15, repeated("49"));
        return 0;
    }
    if (scenario == "unknown-no-retransmit") {
        auto final = ready_for_submit(
            fixed.channel(), projection, selected);
        auto attempted = fixed.channel().after_testnet_submit_attempted(
            std::move(final), 14, repeated("49"));
        fixed.channel().after_testnet_submit_unknown(
            std::move(attempted), 15, repeated("49"));
        (void)fixed.channel().after_testnet_submit_acknowledged(
            std::move(attempted), 16, repeated("49"));
        return 0;
    }
    if (scenario == "txid-mismatch") {
        auto final = ready_for_submit(
            fixed.channel(), projection, selected);
        auto attempted = fixed.channel().after_testnet_submit_attempted(
            std::move(final), 14, repeated("49"));
        (void)fixed.channel().after_testnet_submit_acknowledged(
            std::move(attempted), 15, repeated("4f"));
        return 0;
    }
    if (scenario == "accepted-case-mismatch") {
        auto final = ready_for_submit(
            fixed.channel(), projection, selected);
        auto attempted = fixed.channel().after_testnet_submit_attempted(
            std::move(final), 14, repeated("49"));
        auto submitted = fixed.channel().after_testnet_submit_acknowledged(
            std::move(attempted), 15, repeated("49"));
        (void)fixed.channel().after_accepted_case(
            std::move(submitted), 16, repeated("4f"), repeated("49"),
            repeated("4a"));
        return 0;
    }
    if (scenario == "reorg-before-refusal") {
        auto final = ready_for_submit(
            fixed.channel(), projection, selected);
        auto attempted = fixed.channel().after_testnet_submit_attempted(
            std::move(final), 14, repeated("49"));
        auto submitted = fixed.channel().after_testnet_submit_acknowledged(
            std::move(attempted), 15, repeated("49"));
        auto accepted = fixed.channel().after_accepted_case(
            std::move(submitted), 16, repeated("45"), repeated("49"),
            repeated("4a"));
        fixed.channel().after_accepted_case_reorged(
            std::move(accepted), 17, repeated("4a"), repeated("4c"), 1);
    }
    if (scenario == "rejected-before-refusal") {
        auto final = ready_for_submit(
            fixed.channel(), projection, selected);
        auto attempted = fixed.channel().after_testnet_submit_attempted(
            std::move(final), 14, repeated("49"));
        auto submitted = fixed.channel().after_testnet_submit_acknowledged(
            std::move(attempted), 15, repeated("49"));
        fixed.channel().after_testnet_submit_rejected(
            std::move(submitted), 16);
    }
    if (scenario == "orphaned-before-refusal") {
        auto final = ready_for_submit(
            fixed.channel(), projection, selected);
        auto attempted = fixed.channel().after_testnet_submit_attempted(
            std::move(final), 14, repeated("49"));
        auto submitted = fixed.channel().after_testnet_submit_acknowledged(
            std::move(attempted), 15, repeated("49"));
        auto accepted = fixed.channel().after_accepted_case(
            std::move(submitted), 16, repeated("45"), repeated("49"),
            repeated("4a"));
        fixed.channel().after_accepted_case_orphaned(
            std::move(accepted), 17);
    }
    if (scenario == "premature-close-after-native-full") {
        auto candidate = fixed.channel().after_candidate_constructed(
            10, repeated("44"), repeated("45"));
        auto r0 = fixed.channel().after_r0_verified(
            std::move(candidate), 11, repeated("46"),
            selected.projection_sha256);
        auto native = fixed.channel().after_native_full_verified(
            std::move(r0), 12, repeated("47"), repeated("45"),
            selected.projection_sha256);
        (void)native;
        throw CaptureRefused();
    }
    if (scenario == "premature-close-after-accepted-case") {
        auto final = ready_for_submit(
            fixed.channel(), projection, selected);
        auto attempted = fixed.channel().after_testnet_submit_attempted(
            std::move(final), 14, repeated("49"));
        auto submitted = fixed.channel().after_testnet_submit_acknowledged(
            std::move(attempted), 15, repeated("49"));
        auto accepted = fixed.channel().after_accepted_case(
            std::move(submitted), 16, repeated("45"), repeated("49"),
            repeated("4a"));
        (void)accepted;
        throw CaptureRefused();
    }
    throw CaptureRefused();
}
} // namespace

int main(int argc, char** argv) {
    try {
        if (argc != 2) throw kpb::capture::CaptureRefused();
        return run(argv[1]);
    } catch (...) {
        static constexpr char message[] =
            "KPB_TERMINAL_CAPTURE_V2_REFUSED\n";
        const auto ignored = ::write(STDERR_FILENO, message,
                                     sizeof(message) - 1);
        (void)ignored;
        return 78;
    }
}
