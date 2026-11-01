#include "testnet_activation_authority.hpp"

#include <algorithm>
#include <exception>
#include <openssl/sha.h>
#include <span>
#include <utility>
#include <vector>

namespace kpb::testnet_activation {
namespace {

using Bytes = std::vector<unsigned char>;

[[noreturn]] void refuse() { throw measurement::Refused(); }
void need(bool value) { if (!value) refuse(); }

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

template<std::size_t Size>
void distinct_nonzero(const std::array<Digest, Size>& values) {
    for (std::size_t left = 0; left < values.size(); ++left) {
        need(nonzero(values[left]));
        for (std::size_t right = left + 1; right < values.size(); ++right)
            need(values[left] != values[right]);
    }
}

void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}

template<std::size_t Size>
void add(Bytes& out, const std::array<Digest, Size>& values) {
    for (const auto& value : values) add(out, value);
}

void text(Bytes& out, const char* value) {
    while (*value) out.push_back(static_cast<unsigned char>(*value++));
}

Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    need(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return result;
}

void add_manifest(Bytes& out,
                  const measurement::FiniteManifestBinding& manifest) {
    add(out, manifest.manifest_identity);
    add(out, manifest.parent_recomputation_identity);
    for (const auto& entry : manifest.entries) {
        out.push_back(static_cast<unsigned char>(entry.component));
        for (const auto* field : {
                 &entry.source_identity, &entry.build_identity,
                 &entry.runtime_identity, &entry.assets_identity,
                 &entry.pinned_executable_identity,
                 &entry.launcher_identity})
            add(out, *field);
    }
}

void add_worker(Bytes& out, const measurement::WorkerBinding& worker) {
    for (const auto* field : {
             &worker.source_identity, &worker.build_identity,
             &worker.runtime_identity, &worker.assets_identity,
             &worker.pinned_executable_identity, &worker.launcher_identity})
        add(out, *field);
}

void integer(Bytes& out, std::uint64_t value, unsigned width = 8) {
    for (unsigned offset = 0; offset < width; ++offset)
        out.push_back(static_cast<unsigned char>(value >> (8 * offset)));
}

template<std::size_t Size>
void integers(Bytes& out, const std::array<std::uint64_t, Size>& values) {
    for (const auto value : values) integer(out, value);
}

void valid_manifest(const measurement::FiniteManifestBinding& manifest) {
    need(nonzero(manifest.manifest_identity) &&
         nonzero(manifest.parent_recomputation_identity) &&
         manifest.manifest_identity != manifest.parent_recomputation_identity &&
         manifest.manifest_identity ==
             measurement::recompute_finite_manifest_identity(
                 manifest.entries));
    for (unsigned index = 0; index < manifest.entries.size(); ++index) {
        const auto& entry = manifest.entries[index];
        need(entry.component ==
             static_cast<measurement::ManifestComponent>(index + 1));
        for (const auto* field : {
                 &entry.source_identity, &entry.build_identity,
                 &entry.runtime_identity, &entry.assets_identity,
                 &entry.pinned_executable_identity,
                 &entry.launcher_identity})
            need(nonzero(*field));
    }
}

void valid_worker(const measurement::WorkerBinding& worker) {
    for (const auto* field : {
             &worker.source_identity, &worker.build_identity,
             &worker.runtime_identity, &worker.assets_identity,
             &worker.pinned_executable_identity, &worker.launcher_identity})
        need(nonzero(*field));
}

measurement::WorkerBinding worker_for(
        const measurement::ManifestEntry& entry) {
    return measurement::WorkerBinding{
        .source_identity = entry.source_identity,
        .build_identity = entry.build_identity,
        .runtime_identity = entry.runtime_identity,
        .assets_identity = entry.assets_identity,
        .pinned_executable_identity = entry.pinned_executable_identity,
        .launcher_identity = entry.launcher_identity,
    };
}

void valid(const CandidateActivationBinding& binding) {
    need(binding.network == NetworkScope::KaspaTestnet10);
    for (const auto* field : {
             &binding.trial, &binding.funding_identity,
             &binding.component_profile, &binding.immutable_tail,
             &binding.comparison_selection, &binding.selection_identity,
             &binding.baseline_run, &binding.candidate_run,
             &binding.baseline_aggregate, &binding.candidate_aggregate,
             &binding.privacy_pass_identity,
             &binding.outer_parent_process,
             &binding.outer_parent_executable,
             &binding.manifest_recomputation_receipt,
             &binding.global_payment_capture_completion})
        need(nonzero(*field));
    need(binding.baseline_run != binding.candidate_run &&
         binding.baseline_aggregate != binding.candidate_aggregate);
    distinct_nonzero(binding.projections);
    distinct_nonzero(binding.registered_driver_completions);
    distinct_nonzero(binding.input_heads);
    distinct_nonzero(binding.successor_heads);
    distinct_nonzero(binding.core_completions);
    distinct_nonzero(binding.proof_completions);
    distinct_nonzero(binding.native_candidate_completions);
    distinct_nonzero(binding.signed_case_completions);
    distinct_nonzero(binding.native_full_completions);
    distinct_nonzero(binding.r0_completions);
    distinct_nonzero(binding.value_conservation_completions);
    distinct_nonzero(binding.native_child_processes);
    distinct_nonzero(binding.native_child_exits);
    need(binding.input_heads[0] != binding.successor_heads[0] &&
         binding.input_heads[1] != binding.successor_heads[1] &&
         binding.input_heads[2] != binding.successor_heads[2] &&
         binding.successor_heads[0] == binding.input_heads[1] &&
         binding.successor_heads[1] == binding.input_heads[2]);
    for (unsigned ordinal = 0; ordinal < 3; ++ordinal) {
        need(binding.input_values_sompi[ordinal] > 0 &&
             binding.successor_values_sompi[ordinal] > 0 &&
             binding.fees_sompi[ordinal] > 0 &&
             binding.fees_sompi[ordinal] <
                 binding.input_values_sompi[ordinal] &&
             binding.input_values_sompi[ordinal] -
                 binding.fees_sompi[ordinal] ==
                 binding.successor_values_sompi[ordinal]);
    }
    need(binding.successor_values_sompi[0] ==
             binding.input_values_sompi[1] &&
         binding.successor_values_sompi[1] ==
             binding.input_values_sompi[2]);
    const std::array<Digest, 30> completion_evidence{
        binding.global_payment_capture_completion,
        binding.registered_driver_completions[0],
        binding.registered_driver_completions[1],
        binding.core_completions[0],
        binding.core_completions[1],
        binding.core_completions[2],
        binding.proof_completions[0],
        binding.proof_completions[1],
        binding.proof_completions[2],
        binding.native_candidate_completions[0],
        binding.native_candidate_completions[1],
        binding.native_candidate_completions[2],
        binding.signed_case_completions[0],
        binding.signed_case_completions[1],
        binding.signed_case_completions[2],
        binding.native_full_completions[0],
        binding.native_full_completions[1],
        binding.native_full_completions[2],
        binding.r0_completions[0],
        binding.r0_completions[1],
        binding.r0_completions[2],
        binding.value_conservation_completions[0],
        binding.value_conservation_completions[1],
        binding.value_conservation_completions[2],
        binding.native_child_processes[0],
        binding.native_child_processes[1],
        binding.native_child_processes[2],
        binding.native_child_exits[0],
        binding.native_child_exits[1],
        binding.native_child_exits[2],
    };
    distinct_nonzero(completion_evidence);
    valid_manifest(binding.finite_manifest);
    need(binding.manifest_recomputation_receipt ==
         binding.finite_manifest.parent_recomputation_identity);
}

Digest binding_identity(const CandidateActivationBinding& binding) {
    Bytes bytes;
    text(bytes, "KPB_TESTNET10_ACTIVATION_BINDING_V2\n");
    bytes.push_back(static_cast<unsigned char>(binding.network));
    for (const auto* field : {
             &binding.trial, &binding.funding_identity,
             &binding.component_profile, &binding.immutable_tail,
             &binding.comparison_selection, &binding.selection_identity,
             &binding.baseline_run, &binding.candidate_run,
             &binding.baseline_aggregate, &binding.candidate_aggregate,
             &binding.privacy_pass_identity})
        add(bytes, *field);
    add(bytes, binding.projections);
    add_manifest(bytes, binding.finite_manifest);
    for (const auto* field : {
             &binding.outer_parent_process,
             &binding.outer_parent_executable,
             &binding.manifest_recomputation_receipt})
        add(bytes, *field);
    add(bytes, binding.registered_driver_completions);
    add(bytes, binding.global_payment_capture_completion);
    add(bytes, binding.input_heads);
    add(bytes, binding.successor_heads);
    add(bytes, binding.core_completions);
    add(bytes, binding.proof_completions);
    add(bytes, binding.native_candidate_completions);
    add(bytes, binding.signed_case_completions);
    add(bytes, binding.native_full_completions);
    add(bytes, binding.r0_completions);
    add(bytes, binding.value_conservation_completions);
    add(bytes, binding.native_child_processes);
    add(bytes, binding.native_child_exits);
    integers(bytes, binding.input_values_sompi);
    integers(bytes, binding.successor_values_sompi);
    integers(bytes, binding.fees_sompi);
    return hash(bytes);
}

Digest safety_identity(const CandidateActivationBinding& binding) {
    Bytes bytes;
    text(bytes, "KPB_PRE_NETWORK_SAFETY_AUTHORITY_V1\n");
    add(bytes, binding_identity(binding));
    return hash(bytes);
}

void valid(const PublicGlobalPaymentCaptureCompletion& capture) {
    need(capture.network == NetworkScope::KaspaTestnet10);
    for (const auto* field : {
             &capture.trial, &capture.funding_identity,
             &capture.component_profile, &capture.immutable_tail,
             &capture.comparison_selection, &capture.selection_identity,
             &capture.candidate_run, &capture.outer_parent_process,
             &capture.outer_parent_executable,
             &capture.manifest_recomputation_receipt,
             &capture.completion_identity})
        need(nonzero(*field));
    distinct_nonzero(capture.projections);
    distinct_nonzero(capture.registered_driver_completions);
    distinct_nonzero(capture.registered_driver_heads);
    valid_manifest(capture.finite_manifest);
    need(capture.manifest_recomputation_receipt ==
         capture.finite_manifest.parent_recomputation_identity);
}

Digest native_completion_identity(
        const PublicNativeCandidateCompletion& candidate) {
    Bytes bytes;
    text(bytes, "KPB_NATIVE_TERMINAL_COMPLETION_V1\n");
    integer(bytes, static_cast<unsigned char>(candidate.network), 1);
    integer(bytes, static_cast<unsigned char>(candidate.kind), 1);
    integer(bytes, candidate.ordinal, 4);
    for (const auto* field : {
             &candidate.trial, &candidate.funding_identity,
             &candidate.component_profile, &candidate.immutable_tail,
             &candidate.input_head, &candidate.successor_head,
             &candidate.projection, &candidate.core, &candidate.proof,
             &candidate.signed_case_completion,
             &candidate.native_full_completion, &candidate.r0_completion,
             &candidate.value_conservation_completion})
        add(bytes, *field);
    add_worker(bytes, candidate.worker);
    for (const auto* field : {
             &candidate.outer_parent_process,
             &candidate.outer_parent_executable,
             &candidate.transport_session, &candidate.offer_identity,
             &candidate.child_process_identity,
             &candidate.child_exit_identity})
        add(bytes, *field);
    integer(bytes, candidate.input_value_sompi);
    integer(bytes, candidate.successor_value_sompi);
    integer(bytes, candidate.fee_sompi);
    integer(bytes, candidate.credentials_verified ? 1 : 0, 1);
    integer(bytes, candidate.offer_acknowledged ? 1 : 0, 1);
    integer(bytes, candidate.clean_exit ? 1 : 0, 1);
    return hash(bytes);
}

Digest native_private_supervisor_identity(
        const PublicNativeCandidateCompletion& candidate,
        std::uint64_t authenticated_child_pid,
        std::uint64_t waited_child_pid, bool child_control_closed) {
    Bytes bytes;
    text(bytes, "KPB_NATIVE_TERMINAL_PRIVATE_SUPERVISOR_V1\n");
    add(bytes, candidate.completion_identity);
    add(bytes, candidate.transport_session);
    add(bytes, candidate.offer_identity);
    add(bytes, candidate.child_process_identity);
    add(bytes, candidate.child_exit_identity);
    integer(bytes, authenticated_child_pid);
    integer(bytes, waited_child_pid);
    integer(bytes, child_control_closed ? 1 : 0, 1);
    return hash(bytes);
}

void valid(const PublicNativeCandidateCompletion& candidate) {
    need(candidate.network == NetworkScope::KaspaTestnet10 &&
         candidate.ordinal < 3 &&
         candidate.kind ==
             static_cast<NativeCandidateKind>(candidate.ordinal + 1));
    for (const auto* field : {
             &candidate.trial, &candidate.funding_identity,
             &candidate.component_profile, &candidate.immutable_tail,
             &candidate.input_head, &candidate.successor_head,
             &candidate.projection, &candidate.core, &candidate.proof,
             &candidate.signed_case_completion,
             &candidate.native_full_completion, &candidate.r0_completion,
             &candidate.value_conservation_completion,
             &candidate.outer_parent_process,
             &candidate.outer_parent_executable,
             &candidate.transport_session, &candidate.offer_identity,
             &candidate.child_process_identity,
             &candidate.child_exit_identity,
             &candidate.completion_identity})
        need(nonzero(*field));
    valid_worker(candidate.worker);
    need(candidate.input_head != candidate.successor_head);
    need(candidate.input_value_sompi > 0 &&
         candidate.successor_value_sompi > 0 &&
         candidate.fee_sompi > 0 &&
         candidate.fee_sompi < candidate.input_value_sompi &&
         candidate.input_value_sompi - candidate.fee_sompi ==
             candidate.successor_value_sompi &&
         candidate.credentials_verified &&
         candidate.offer_acknowledged && candidate.clean_exit &&
         candidate.completion_identity ==
             native_completion_identity(candidate));
    distinct_nonzero(std::array<Digest, 10>{
        candidate.core,
        candidate.proof,
        candidate.signed_case_completion,
        candidate.native_full_completion,
        candidate.r0_completion,
        candidate.value_conservation_completion,
        candidate.child_process_identity,
        candidate.child_exit_identity,
        candidate.offer_identity,
        candidate.completion_identity,
    });
}

void valid_native_private_supervisor(
        const PublicNativeCandidateCompletion& candidate,
        std::uint64_t authenticated_child_pid,
        std::uint64_t waited_child_pid, bool child_control_closed,
        const Digest& private_supervisor_identity) {
    need(authenticated_child_pid > 1 &&
         authenticated_child_pid == waited_child_pid &&
         child_control_closed && nonzero(private_supervisor_identity) &&
         private_supervisor_identity == native_private_supervisor_identity(
             candidate, authenticated_child_pid, waited_child_pid,
             child_control_closed) &&
         private_supervisor_identity != candidate.completion_identity &&
         private_supervisor_identity != candidate.child_process_identity &&
         private_supervisor_identity != candidate.child_exit_identity);
}

void valid(const measurement::PublicBatchPrivacyPass& pass) {
    need(pass.scope ==
         measurement::PrivacyScope::BatchPaymentPreNetworkOnly);
    valid_manifest(pass.selection.finite_manifest);
    valid_worker(pass.selection.comparison_worker);
    need(pass.selection.comparison_worker == worker_for(
        pass.selection.finite_manifest.entries.at(9)));
    for (const auto* field : {
             &pass.selection.comparison_selection,
             &pass.selection.selection_identity, &pass.selection.method,
             &pass.selection.workload, &pass.selection.source_closure,
             &pass.selection.runtime, &pass.selection.outer_parent_process,
             &pass.selection.outer_parent_executable,
             &pass.selection.manifest_recomputation_receipt,
             &pass.selection.baseline_run, &pass.selection.candidate_run,
             &pass.comparison_selection, &pass.baseline_aggregate,
             &pass.candidate_aggregate, &pass.candidate_trial,
             &pass.owner_comparison_child_exit,
             &pass.owner_comparison_process,
             &pass.owner_comparison_receipt,
             &pass.finite_manifest_identity, &pass.outer_parent_process,
             &pass.outer_parent_executable,
             &pass.manifest_recomputation_receipt, &pass.pass_identity})
        need(nonzero(*field));
    distinct_nonzero(pass.candidate_projections);
    need(pass.selection.baseline_run != pass.selection.candidate_run &&
         pass.baseline_aggregate != pass.candidate_aggregate &&
         pass.comparison_selection == pass.selection.comparison_selection &&
         pass.finite_manifest_identity ==
             pass.selection.finite_manifest.manifest_identity &&
         pass.outer_parent_process == pass.selection.outer_parent_process &&
         pass.outer_parent_executable ==
             pass.selection.outer_parent_executable &&
         pass.manifest_recomputation_receipt ==
             pass.selection.manifest_recomputation_receipt &&
         pass.manifest_recomputation_receipt ==
             pass.selection.finite_manifest.parent_recomputation_identity);
}

void exact(const CandidateActivationBinding& selected,
           const measurement::PublicBatchPrivacyPass& pass) {
    need(selected.trial == pass.candidate_trial &&
         selected.projections == pass.candidate_projections &&
         selected.comparison_selection == pass.comparison_selection &&
         selected.selection_identity == pass.selection.selection_identity &&
         selected.baseline_run == pass.selection.baseline_run &&
         selected.candidate_run == pass.selection.candidate_run &&
         selected.baseline_aggregate == pass.baseline_aggregate &&
         selected.candidate_aggregate == pass.candidate_aggregate &&
         selected.privacy_pass_identity == pass.pass_identity &&
         selected.finite_manifest == pass.selection.finite_manifest &&
         selected.outer_parent_process == pass.outer_parent_process &&
         selected.outer_parent_executable == pass.outer_parent_executable &&
         selected.manifest_recomputation_receipt ==
             pass.manifest_recomputation_receipt);
}

Digest permit_identity(const CandidateActivationBinding& binding,
                       const Digest& privacy, const Digest& safety) {
    Bytes bytes;
    text(bytes, "KPB_TESTNET10_ACTIVATION_PERMIT_V1\n");
    add(bytes, binding_identity(binding));
    add(bytes, privacy);
    add(bytes, safety);
    return hash(bytes);
}

} // namespace

Digest recompute_native_candidate_completion_identity(
        const PublicNativeCandidateCompletion& candidate) {
    return native_completion_identity(candidate);
}

GlobalPaymentCaptureCompletionAuthority::
GlobalPaymentCaptureCompletionAuthority(
        PublicGlobalPaymentCaptureCompletion receipt)
    : receipt_(std::move(receipt)) {
    valid(receipt_);
}

GlobalPaymentCaptureCompletionAuthority::
GlobalPaymentCaptureCompletionAuthority(
        GlobalPaymentCaptureCompletionAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}

#ifdef KPB_TESTNET_ACTIVATION_AUTHORITY_TEST_SETUP
GlobalPaymentCaptureCompletionAuthority
GlobalPaymentCaptureCompletionAuthority::test_only_mint(
        PublicGlobalPaymentCaptureCompletion receipt) {
    return GlobalPaymentCaptureCompletionAuthority(std::move(receipt));
}
#endif

NativeCandidateCompletionAuthority::NativeCandidateCompletionAuthority(
        PublicNativeCandidateCompletion receipt,
        std::uint64_t authenticated_child_pid,
        std::uint64_t waited_child_pid, bool child_control_closed)
    : receipt_(std::move(receipt)),
      evidence_{
          .authenticated_child_pid = authenticated_child_pid,
          .waited_child_pid = waited_child_pid,
          .child_control_closed = child_control_closed,
          .private_supervisor_identity =
              native_private_supervisor_identity(
                  receipt_, authenticated_child_pid, waited_child_pid,
                  child_control_closed),
      } {
    valid(receipt_);
    valid_native_private_supervisor(
        receipt_, evidence_.authenticated_child_pid,
        evidence_.waited_child_pid, evidence_.child_control_closed,
        evidence_.private_supervisor_identity);
}

NativeCandidateCompletionAuthority::NativeCandidateCompletionAuthority(
        NativeCandidateCompletionAuthority&& other) noexcept
    : receipt_(other.receipt_), evidence_(other.evidence_),
      live_(other.live_.exchange(false)) {}

PreNetworkSafetyJoin PreNetworkSafetyFactory::join(
        measurement::BatchPrivacyPassAuthority&& supplied_privacy,
        GlobalPaymentCaptureCompletionAuthority&& supplied_capture,
        std::array<NativeCandidateCompletionAuthority, 3>&& supplied_native) {
    std::optional<measurement::BatchPrivacyPassAuthority> privacy_authority;
    bool privacy_live = false;
    try {
        privacy_authority.emplace(
            std::move(supplied_privacy).transfer_for_pre_network_safety());
        privacy_live = true;
    } catch (...) {
        // Burn the capture/native side below as well. One failed input cannot
        // be replaced while reusing the others.
    }
    const bool capture_live = supplied_capture.live_.exchange(false);
    std::array<bool, 3> native_live{};
    for (unsigned ordinal = 0; ordinal < supplied_native.size(); ++ordinal)
        native_live[ordinal] =
            supplied_native[ordinal].live_.exchange(false);
    need(privacy_live && capture_live && native_live[0] && native_live[1] &&
         native_live[2] && privacy_authority.has_value());
    const auto& privacy = privacy_authority->public_receipt();
    valid(privacy);
    valid(supplied_capture.receipt_);
    for (const auto& authority : supplied_native) {
        valid(authority.receipt_);
        valid_native_private_supervisor(
            authority.receipt_,
            authority.evidence_.authenticated_child_pid,
            authority.evidence_.waited_child_pid,
            authority.evidence_.child_control_closed,
            authority.evidence_.private_supervisor_identity);
    }

    const auto& capture = supplied_capture.receipt_;
    const auto& genesis = supplied_native[0].receipt_;
    const auto& round1 = supplied_native[1].receipt_;
    const auto& round2 = supplied_native[2].receipt_;
    need(capture.trial == privacy.candidate_trial &&
         capture.comparison_selection == privacy.comparison_selection &&
         capture.selection_identity == privacy.selection.selection_identity &&
         capture.candidate_run == privacy.selection.candidate_run &&
         capture.projections == privacy.candidate_projections &&
         capture.finite_manifest == privacy.selection.finite_manifest &&
         capture.outer_parent_process == privacy.outer_parent_process &&
         capture.outer_parent_executable ==
             privacy.outer_parent_executable &&
         capture.manifest_recomputation_receipt ==
             privacy.manifest_recomputation_receipt);

    for (const auto& candidate : {&genesis, &round1, &round2})
        need(candidate->network == capture.network &&
             candidate->trial == capture.trial &&
             candidate->funding_identity == capture.funding_identity &&
             candidate->component_profile == capture.component_profile &&
             candidate->immutable_tail == capture.immutable_tail);
    need(genesis.ordinal == 0 &&
         genesis.kind == NativeCandidateKind::Genesis &&
         round1.ordinal == 1 &&
         round1.kind == NativeCandidateKind::PaymentRound1 &&
         round2.ordinal == 2 &&
         round2.kind == NativeCandidateKind::PaymentRound2 &&
         genesis.successor_head == round1.input_head &&
         round1.successor_head == round2.input_head &&
         capture.registered_driver_heads ==
             std::array<Digest, 2>{round1.input_head, round2.input_head} &&
         round1.projection == capture.projections[0] &&
         round2.projection == capture.projections[1]);

    CandidateActivationBinding selected{
        .network = capture.network,
        .trial = capture.trial,
        .funding_identity = capture.funding_identity,
        .component_profile = capture.component_profile,
        .immutable_tail = capture.immutable_tail,
        .comparison_selection = privacy.comparison_selection,
        .selection_identity = privacy.selection.selection_identity,
        .baseline_run = privacy.selection.baseline_run,
        .candidate_run = privacy.selection.candidate_run,
        .baseline_aggregate = privacy.baseline_aggregate,
        .candidate_aggregate = privacy.candidate_aggregate,
        .privacy_pass_identity = privacy.pass_identity,
        .projections = privacy.candidate_projections,
        .finite_manifest = privacy.selection.finite_manifest,
        .outer_parent_process = privacy.outer_parent_process,
        .outer_parent_executable = privacy.outer_parent_executable,
        .manifest_recomputation_receipt =
            privacy.manifest_recomputation_receipt,
        .global_payment_capture_completion = capture.completion_identity,
        .registered_driver_completions =
            capture.registered_driver_completions,
        .input_heads = {
            genesis.input_head, round1.input_head, round2.input_head},
        .successor_heads = {genesis.successor_head,
                            round1.successor_head, round2.successor_head},
        .core_completions = {genesis.core, round1.core, round2.core},
        .proof_completions = {genesis.proof, round1.proof, round2.proof},
        .native_candidate_completions = {genesis.completion_identity,
            round1.completion_identity, round2.completion_identity},
        .signed_case_completions = {genesis.signed_case_completion,
            round1.signed_case_completion, round2.signed_case_completion},
        .native_full_completions = {genesis.native_full_completion,
            round1.native_full_completion, round2.native_full_completion},
        .r0_completions = {genesis.r0_completion, round1.r0_completion,
                           round2.r0_completion},
        .value_conservation_completions = {
            genesis.value_conservation_completion,
            round1.value_conservation_completion,
            round2.value_conservation_completion},
        .native_child_processes = {genesis.child_process_identity,
            round1.child_process_identity, round2.child_process_identity},
        .native_child_exits = {genesis.child_exit_identity,
            round1.child_exit_identity, round2.child_exit_identity},
        .input_values_sompi = {genesis.input_value_sompi,
            round1.input_value_sompi, round2.input_value_sompi},
        .successor_values_sompi = {genesis.successor_value_sompi,
            round1.successor_value_sompi,
            round2.successor_value_sompi},
        .fees_sompi = {genesis.fee_sompi, round1.fee_sompi,
                       round2.fee_sompi},
    };
    valid(selected);
    exact(selected, privacy);
    auto safety = PreNetworkSafetyAuthority(std::move(selected));
    return PreNetworkSafetyJoin(
        std::move(*privacy_authority), std::move(safety));
}

PreNetworkSafetyAuthority::PreNetworkSafetyAuthority(
        CandidateActivationBinding binding) {
    valid(binding);
    receipt_ = PublicPreNetworkSafety{
        .scope = binding.network,
        .binding = std::move(binding),
    };
    receipt_.safety_identity = safety_identity(receipt_.binding);
}

PreNetworkSafetyAuthority::PreNetworkSafetyAuthority(
        PreNetworkSafetyAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}

PreNetworkSafetyJoin::PreNetworkSafetyJoin(
        measurement::BatchPrivacyPassAuthority&& privacy,
        PreNetworkSafetyAuthority&& safety)
    : privacy_(std::in_place, std::move(privacy)),
      safety_(std::in_place, std::move(safety)) {}

PreNetworkSafetyJoin::PreNetworkSafetyJoin(
        PreNetworkSafetyJoin&& other) noexcept
    : privacy_(std::move(other.privacy_)),
      safety_(std::move(other.safety_)),
      live_(other.live_.exchange(false)) {}

TestnetActivationPermit::TestnetActivationPermit(
        PublicTestnetActivationPermit receipt)
    : receipt_(std::move(receipt)) {}

TestnetActivationPermit::TestnetActivationPermit(
        TestnetActivationPermit&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}

TestnetActivationPermit ActivationJoiner::conjoin(
        PreNetworkSafetyJoin&& joined) {
    need(joined.live_.exchange(false) && joined.privacy_.has_value() &&
         joined.safety_.has_value());
    auto privacy = std::move(*joined.privacy_);
    auto safety = std::move(*joined.safety_);
    joined.privacy_.reset();
    joined.safety_.reset();
    measurement::PublicBatchPrivacyPass privacy_receipt{};
    bool privacy_live = false;
    try {
        privacy_receipt = privacy.consume_for_testnet_activation();
        privacy_live = true;
    } catch (...) {
        // Still consume the safety side below. A failed conjunction cannot be
        // retried by replacing only one input capability.
    }
    const bool safety_live = safety.live_.exchange(false);
    need(privacy_live && safety_live);
    const auto& selected = safety.receipt_.binding;
    valid(selected);
    valid(privacy_receipt);
    need(safety.receipt_.scope == NetworkScope::KaspaTestnet10 &&
         safety.receipt_.safety_identity == safety_identity(selected));
    exact(selected, privacy_receipt);
    PublicTestnetActivationPermit receipt{
        .scope = NetworkScope::KaspaTestnet10,
        .binding = selected,
        .privacy_pass_identity = privacy_receipt.pass_identity,
        .safety_identity = safety.receipt_.safety_identity,
    };
    receipt.permit_identity = permit_identity(
        selected, receipt.privacy_pass_identity, receipt.safety_identity);
    return TestnetActivationPermit(std::move(receipt));
}

SelectedParentAuthority::SelectedParentAuthority(
        PublicSelectedParent receipt) : receipt_(std::move(receipt)) {
    valid(receipt_.binding);
    need(receipt_.network == NetworkScope::KaspaTestnet10 &&
         receipt_.network == receipt_.binding.network &&
         nonzero(receipt_.selected_rpc_identity) &&
         nonzero(receipt_.parent_identity) &&
         receipt_.selected_rpc_identity != receipt_.parent_identity);
}

SelectedParentAuthority::SelectedParentAuthority(
        SelectedParentAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}

#ifdef KPB_TESTNET_ACTIVATION_AUTHORITY_TEST_SETUP
SelectedParentAuthority SelectedParentAuthority::test_only_mint(
        PublicSelectedParent receipt) {
    return SelectedParentAuthority(std::move(receipt));
}
#endif

FirstRpcBoundaryAuthority::FirstRpcBoundaryAuthority(
        PublicFirstRpcBoundary receipt) : receipt_(std::move(receipt)) {}

FirstRpcBoundaryAuthority::FirstRpcBoundaryAuthority(
        FirstRpcBoundaryAuthority&& other) noexcept
    : receipt_(other.receipt_), live_(other.live_.exchange(false)) {}

SelectedParentNetworkBoundary::SelectedParentNetworkBoundary(
        PublicSelectedParent parent) : parent_(std::move(parent)) {}

SelectedParentNetworkBoundary SelectedParentNetworkBoundary::open(
        SelectedParentAuthority&& authority) {
    need(authority.live_.exchange(false));
    valid(authority.receipt_.binding);
    need(authority.receipt_.network == NetworkScope::KaspaTestnet10 &&
         authority.receipt_.network == authority.receipt_.binding.network &&
         nonzero(authority.receipt_.selected_rpc_identity) &&
         nonzero(authority.receipt_.parent_identity) &&
         authority.receipt_.selected_rpc_identity !=
             authority.receipt_.parent_identity);
    return SelectedParentNetworkBoundary(authority.receipt_);
}

FirstRpcBoundaryAuthority
SelectedParentNetworkBoundary::authorize_first_rpc(
        TestnetActivationPermit&& permit) {
    std::lock_guard guard(mutex_);
    try {
        const bool permit_live = permit.live_.exchange(false);
        need(state_ == State::AwaitingPermit && permit_live);
        valid(permit.receipt_.binding);
        need(permit.receipt_.scope == NetworkScope::KaspaTestnet10 &&
             permit.receipt_.scope == parent_.network &&
             permit.receipt_.binding == parent_.binding &&
             permit.receipt_.privacy_pass_identity ==
                 permit.receipt_.binding.privacy_pass_identity &&
             nonzero(permit.receipt_.safety_identity) &&
             nonzero(permit.receipt_.permit_identity));
        PublicFirstRpcBoundary receipt{
            .scope = NetworkScope::KaspaTestnet10,
            .binding = parent_.binding,
            .selected_rpc_identity = parent_.selected_rpc_identity,
            .selected_parent_identity = parent_.parent_identity,
            .activation_permit_identity = permit.receipt_.permit_identity,
            .network_invoked = false,
        };
        Bytes bytes;
        text(bytes, "KPB_TESTNET10_FIRST_RPC_BOUNDARY_V1\n");
        add(bytes, binding_identity(receipt.binding));
        add(bytes, receipt.selected_rpc_identity);
        add(bytes, receipt.selected_parent_identity);
        add(bytes, receipt.activation_permit_identity);
        receipt.boundary_identity = hash(bytes);
        state_ = State::Completed;
        return FirstRpcBoundaryAuthority(std::move(receipt));
    } catch (...) {
        state_ = State::Poisoned;
        refuse();
    }
}

} // namespace kpb::testnet_activation
