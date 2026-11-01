#include "privacy_measurement_authority.hpp"
#include "native_terminal_completion.hpp"

namespace kpb::measurement {
namespace {

[[noreturn]] void refuse_native_match() { throw Refused(); }
void require_native_match(bool value) {
    if (!value) refuse_native_match();
}

} // namespace

kpb::native_terminal::MatchedNativeTerminalProducerBundle
ProducerClosureAuthority::match_native_terminal_streams(
        kpb::native_terminal::PaymentLifecycleCompletionAuthority&& round1,
        kpb::native_terminal::PaymentLifecycleCompletionAuthority&& round2)
        && {
    const bool producer_live = live_.exchange(false);
    const bool round1_live = round1.live_.exchange(false);
    const bool round2_live = round2.live_.exchange(false);
    require_native_match(producer_live && round1_live && round2_live);

    validate_for_native_terminal_join();
    round1.validate_for_native_terminal_join();
    round2.validate_for_native_terminal_join();
    const auto& first = round1.receipt_;
    const auto& second = round2.receipt_;
    require_native_match(
        first.native.kind ==
            kpb::testnet_activation::NativeCandidateKind::PaymentRound1 &&
        first.native.ordinal == 1 &&
        second.native.kind ==
            kpb::testnet_activation::NativeCandidateKind::PaymentRound2 &&
        second.native.ordinal == 2 &&
        first.producer_binding == receipt_.binding &&
        second.producer_binding == receipt_.binding &&
        first.native.trial == receipt_.binding.trial &&
        second.native.trial == receipt_.binding.trial &&
        first.native.projection == receipt_.binding.projections[0] &&
        second.native.projection == receipt_.binding.projections[1] &&
        first.native.outer_parent_process ==
            receipt_.binding.outer_parent_process &&
        second.native.outer_parent_process ==
            receipt_.binding.outer_parent_process &&
        first.native.outer_parent_executable ==
            receipt_.binding.outer_parent_executable &&
        second.native.outer_parent_executable ==
            receipt_.binding.outer_parent_executable &&
        kpb::native_terminal::exact_capture_lineage(
            receipt_.binding, 1, round1.evidence_.capture_binding) &&
        kpb::native_terminal::exact_capture_lineage(
            receipt_.binding, 2, round2.evidence_.capture_binding) &&
        first.opaque_lifecycle_authority_identity !=
            second.opaque_lifecycle_authority_identity);

    constexpr std::array<unsigned, 2> indexes{1, 6};
    const std::array<
        kpb::native_terminal::PaymentLifecycleCompletionAuthority*, 2>
        lifecycle{&round1, &round2};
    for (unsigned round = 0; round < 2; ++round) {
        const unsigned index = indexes[round];
        const auto& stream = receipt_.streams[index];
        const auto& private_stream = evidence_.streams[index];
        const auto& public_native = lifecycle[round]->receipt_;
        const auto& private_native = lifecycle[round]->evidence_;
        require_native_match(
            stream.round == round + 1 &&
            stream.kind == CaptureKind::TerminalHistory &&
            stream.fixed_fd == (round == 0 ? 21U : 26U) &&
            stream.process_identity ==
                public_native.stream_process_identity &&
            stream.child_exit_identity ==
                public_native.stream_child_exit_identity &&
            stream.root_closed && stream.end_observed &&
            stream.eof_observed &&
            private_stream.record_root == private_native.record_root &&
            private_stream.end_frame_identity ==
                private_native.end_frame_identity &&
            private_stream.eof_identity ==
                private_native.expected_eof_identity &&
            private_stream.record_count == private_native.record_count &&
            private_stream.payload_bytes == private_native.payload_bytes &&
            private_stream.raw_wire_bytes ==
                private_native.raw_wire_bytes &&
            private_native.end_written && private_native.writer_closed);
    }

    ProducerClosureAuthority producer_continuation(receipt_, evidence_);
    kpb::native_terminal::PaymentLifecycleCompletionAuthority
        round1_continuation(round1.receipt_, round1.evidence_);
    kpb::native_terminal::PaymentLifecycleCompletionAuthority
        round2_continuation(round2.receipt_, round2.evidence_);
    return kpb::native_terminal::MatchedNativeTerminalProducerBundle(
        std::move(producer_continuation), std::move(round1_continuation),
        std::move(round2_continuation));
}

} // namespace kpb::measurement
