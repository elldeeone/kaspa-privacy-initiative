#include "privacy_measurement_authority.hpp"

#include <array>
#include <atomic>
#include <cassert>
#include <thread>
#include <type_traits>

using namespace kpb::measurement;

static_assert(static_cast<unsigned char>(Classification::HiddenCandidate) ==
              1);
static_assert(static_cast<unsigned char>(
                  Classification::TransparentBaseline) == 2);

namespace {

template<class Value>
concept HasRecordRoot = requires(Value value) { value.record_root; };

template<class Value>
concept HasEndFrameIdentity = requires(Value value) {
    value.end_frame_identity;
};

template<class Value>
concept HasEofIdentity = requires(Value value) { value.eof_identity; };

template<class Value>
concept HasProducerReceipt = requires(Value value) {
    value.producer_receipt;
};

template<class Value>
concept HasProducerIdentity = requires(Value value) {
    value.producer_identity;
};

template<class Value>
concept HasProducerChildExit = requires(Value value) {
    value.producer_child_exit;
};

template<class Value>
concept HasRecordCount = requires(Value value) { value.record_count; };

template<class Value>
concept HasPayloadBytes = requires(Value value) { value.payload_bytes; };

template<class Value>
concept HasRawWireBytes = requires(Value value) { value.raw_wire_bytes; };

template<class Value>
concept HasTruthReleaseConsume = requires(Value value) {
    std::move(value).consume_for_truth_endpoint();
};

template<class Value>
concept CanSplitTruthRelease = requires(Value value) {
    std::move(value).split_for_truth_release();
};

template<class Authority>
concept CanUnlockGlobalCandidateTruth = requires(
    kpi::mpc::financial::fresh_owner_issuance::
        FreshOwnerProcessSupervisor& supervisor,
    Authority authority,
    kpi::mpc::financial::fresh_owner_issuance::
        CandidateOwnerTruthPendingAuthority&& pending) {
    kpi::mpc::financial::fresh_owner_issuance::
        CandidateOwnerTruthPostBarrierBridge::release(
            supervisor, std::move(authority), std::move(pending));
};

static_assert(!HasRecordRoot<PublicStreamClosure>);
static_assert(!HasEndFrameIdentity<PublicStreamClosure>);
static_assert(!HasEofIdentity<PublicStreamClosure>);
static_assert(!HasRecordCount<PublicStreamClosure>);
static_assert(!HasPayloadBytes<PublicStreamClosure>);
static_assert(!HasRawWireBytes<PublicStreamClosure>);
static_assert(!HasProducerReceipt<PublicProducerClosure>);
static_assert(!HasProducerIdentity<PublicProducerClosure>);
static_assert(!HasProducerChildExit<PublicProducerClosure>);
static_assert(!HasProducerReceipt<PublicTrialCaptureCompletion>);
static_assert(!HasProducerIdentity<PublicTrialCaptureCompletion>);
static_assert(!HasProducerChildExit<PublicTrialCaptureCompletion>);
static_assert(!std::is_copy_constructible_v<
              OwnerTruthReleasePermitAuthority>);
static_assert(!std::is_constructible_v<
              OwnerTruthReleasePermitAuthority,
              PublicOwnerTruthReleasePermit>);
static_assert(!HasTruthReleaseConsume<OwnerTruthReleasePermitAuthority>);
static_assert(!CanSplitTruthRelease<
              OwnerScoreExecutionPermitAuthority>);
static_assert(!CanUnlockGlobalCandidateTruth<OwnerScorePermitAuthority>);
static_assert(!CanUnlockGlobalCandidateTruth<
              OwnerTruthReleasePermitAuthority>);
static_assert(!std::is_copy_constructible_v<
              CandidateTruthBarrierReleaseAuthority>);
static_assert(!std::is_constructible_v<
              CandidateTruthBarrierReleaseAuthority,
              PublicCandidateTruthBarrierRelease>);

template <class Function>
void expect_refused(Function&& function) {
    bool refused = false;
    try {
        function();
    } catch (const Refused&) {
        refused = true;
    }
    assert(refused);
}

Digest digest(unsigned char value) {
    Digest result{};
    result.fill(value);
    return result;
}

OwnerScoreExecutionPermitAuthority execution_permit(
        OwnerScorePermitAuthority&& permit) {
    auto split = std::move(permit).split_for_truth_release();
    auto release = split.take_truth_release_permit();
    (void)release;
    return split.take_execution_permit();
}

WorkerBinding worker(const ManifestEntry& entry) {
    return WorkerBinding{
        .source_identity = entry.source_identity,
        .build_identity = entry.build_identity,
        .runtime_identity = entry.runtime_identity,
        .assets_identity = entry.assets_identity,
        .pinned_executable_identity = entry.pinned_executable_identity,
        .launcher_identity = entry.launcher_identity,
    };
}

FiniteManifestBinding finite_manifest() {
    std::array<ManifestEntry, 10> entries{};
    for (unsigned index = 0; index < entries.size(); ++index) {
        const auto seed = static_cast<unsigned char>(0xd0 + index);
        entries[index] = ManifestEntry{
            .component = static_cast<ManifestComponent>(index + 1),
            .source_identity = digest(seed),
            .build_identity = digest(static_cast<unsigned char>(seed + 1)),
            .runtime_identity = digest(static_cast<unsigned char>(seed + 2)),
            .assets_identity = digest(static_cast<unsigned char>(seed + 3)),
            .pinned_executable_identity =
                digest(static_cast<unsigned char>(seed + 4)),
            .launcher_identity = digest(static_cast<unsigned char>(seed + 5)),
        };
    }
    return FiniteManifestBinding{
        .manifest_identity = recompute_finite_manifest_identity(entries),
        .parent_recomputation_identity = digest(0xcf),
        .entries = entries,
    };
}

RunBinding binding(Classification classification, unsigned char run) {
    const auto manifest = finite_manifest();
    const auto& capture = manifest.entries.at(1);
    return RunBinding{
        .classification = classification,
        .comparison_selection = digest(0x10),
        .run_selection = digest(run),
        .trial = digest(run + 1),
        .attempt = digest(run + 2),
        .cohort = digest(run + 3),
        .capture = digest(run + 4),
        .method = digest(0x20),
        .workload = digest(0x21),
        .source_closure = digest(0x22),
        .runtime = digest(0x23),
        .finite_manifest = manifest,
        .outer_parent_process = digest(0xc1),
        .outer_parent_executable = digest(0xc2),
        .capture_source = capture.source_identity,
        .capture_build = capture.build_identity,
        .capture_runtime = capture.runtime_identity,
        .capture_launcher = capture.launcher_identity,
        .observer_worker = worker(manifest.entries.at(6)),
        .score_worker = worker(manifest.entries.at(7)),
        .aggregate_worker = worker(manifest.entries.at(8)),
        .financial_runs = {digest(run + 5), digest(run + 6)},
        .round_attempts = {digest(run + 9), digest(run + 10)},
        .round_cohorts = {digest(run + 11), digest(run + 12)},
        .round_capture_plans = {digest(run + 13), digest(run + 14)},
        .projections = {digest(run + 7), digest(run + 8)},
    };
}

ParentManifestRecomputationAuthority parent_manifest(
        const RunBinding& selected) {
    return ParentManifestRecomputationAuthority::test_only_mint(
        PublicParentManifestRecomputation{
            .manifest = selected.finite_manifest,
            .parent_process_identity = selected.outer_parent_process,
            .parent_executable_identity = selected.outer_parent_executable,
            .recomputation_receipt =
                selected.finite_manifest.parent_recomputation_identity,
        });
}

PartyCompletionAuthority party(const RunBinding& selected, unsigned round,
                               unsigned role) {
    return PartyCompletionAuthority::test_only_mint(PublicPartyCompletion{
        .binding = selected,
        .round = round,
        .role = role,
        .financial_run = selected.financial_runs.at(round - 1),
        .trial = selected.trial,
        .attempt = selected.round_attempts.at(round - 1),
        .cohort = selected.round_cohorts.at(round - 1),
        .child_exit = digest(static_cast<unsigned char>(0x40 + 3 * round + role)),
        .driver_completion = digest(static_cast<unsigned char>(0x50 + 3 * round + role)),
        .selection_identity = digest(0x5d),
        .proposal_identity = digest(
            static_cast<unsigned char>(0x5e + 3 * round + role)),
        .accepted_head = digest(static_cast<unsigned char>(0x60 + round)),
        .postlock_accepted_head = digest(
            static_cast<unsigned char>(0x60 + round)),
        .durable_lock = digest(static_cast<unsigned char>(0x70 + round)),
        .capture_source = selected.capture_source,
        .capture_build = selected.capture_build,
        .capture_runtime = selected.capture_runtime,
        .capture_launcher = selected.capture_launcher,
        .process_identity = digest(
            static_cast<unsigned char>(0x75 + 3 * round + role)),
        .egress = digest(static_cast<unsigned char>(0x80 + round)),
        .proof = digest(static_cast<unsigned char>(0x90 + round)),
        .projection = selected.projections.at(round - 1),
    });
}

ProducerClosureAuthority producer(const RunBinding& selected) {
    std::array<PublicStreamClosure, 10> streams{};
    ProducerClosureEvidence evidence{
        .opaque_closure_authority_identity = digest(0xa9),
        .producer_child_exit = digest(0xa1),
        .producer_receipt = digest(0xa2),
        .producer_identity = digest(0xa3),
    };
    for (unsigned round = 1; round <= 2; ++round) {
        for (unsigned kind = 0; kind < 5; ++kind) {
            const unsigned index = (round - 1) * 5 + kind;
            constexpr std::array<unsigned, 5> manifest_indexes{0, 3, 4, 1, 2};
            const auto& entry =
                selected.finite_manifest.entries.at(manifest_indexes[kind]);
            streams[index] = PublicStreamClosure{
                .round = round,
                .kind = static_cast<CaptureKind>(kind + 1),
                .fixed_fd = 20 + index,
                .manifest_component = entry.component,
                .source_identity = entry.source_identity,
                .build_identity = entry.build_identity,
                .runtime_identity = entry.runtime_identity,
                .launcher_identity = entry.launcher_identity,
                .process_identity = digest(
                    static_cast<unsigned char>(0x41 + index)),
                .child_exit_identity = digest(
                    static_cast<unsigned char>(0x81 + index)),
                .root_closed = true,
                .end_observed = true,
                .eof_observed = true,
            };
            evidence.streams[index] = ProducerStreamClosureEvidence{
                .record_root = digest(
                    static_cast<unsigned char>(0x51 + index)),
                .end_frame_identity = digest(
                    static_cast<unsigned char>(0x61 + index)),
                .eof_identity = digest(
                    static_cast<unsigned char>(0x71 + index)),
                .record_count = 3 + index,
                .payload_bytes = 100 + index,
                .raw_wire_bytes = 200 + index,
            };
        }
    }
    return ProducerClosureAuthority::test_only_mint(PublicProducerClosure{
        .binding = selected,
        .opaque_closure_authority_identity = digest(0xa9),
        .producer_worker = worker(selected.finite_manifest.entries.at(5)),
        .producer_process_identity = digest(0xa7),
        .role_closure_identity = digest(0xa4),
        .manifest_seal = digest(0xa5),
        .construction_policy = selected.classification ==
                Classification::TransparentBaseline
            ? ConstructionPolicy::ExplicitOwnerPublicEffects
            : ConstructionPolicy::SecretPermutationIndependent,
        .construction_classification_receipt = digest(0xa8),
        .streams = streams,
        .stream_count = 10,
        .closed_root_count = 10,
        .unknown_record_count = 0,
    }, std::move(evidence));
}

ProducerClosureEvidence producer_evidence() {
    ProducerClosureEvidence evidence{
        .opaque_closure_authority_identity = digest(0xa9),
        .producer_child_exit = digest(0xa1),
        .producer_receipt = digest(0xa2),
        .producer_identity = digest(0xa3),
    };
    for (unsigned index = 0; index < evidence.streams.size(); ++index)
        evidence.streams[index] = ProducerStreamClosureEvidence{
            .record_root = digest(
                static_cast<unsigned char>(0x51 + index)),
            .end_frame_identity = digest(
                static_cast<unsigned char>(0x61 + index)),
            .eof_identity = digest(
                static_cast<unsigned char>(0x71 + index)),
            .record_count = 3 + index,
            .payload_bytes = 100 + index,
            .raw_wire_bytes = 200 + index,
        };
    return evidence;
}

template<class Authority>
concept NativeTerminalTransferable = requires(Authority&& authority) {
    std::forward<Authority>(authority)
        .transfer_for_native_terminal_join();
};

static_assert(NativeTerminalTransferable<ProducerClosureAuthority>);
static_assert(!NativeTerminalTransferable<ProducerClosureAuthority&>);

void producer_native_terminal_transfer_is_exact_and_one_shot() {
    const auto selected = binding(Classification::HiddenCandidate, 0x32);
    auto original = producer(selected);
    const auto expected = original.public_receipt();
    auto continuation =
        std::move(original).transfer_for_native_terminal_join();
    assert(continuation.public_receipt() == expected);
    expect_refused([&] {
        (void)std::move(original).transfer_for_native_terminal_join();
    });

    TrialCaptureJoiner joiner(selected, parent_manifest(selected));
    for (unsigned round = 1; round <= 2; ++round)
        for (unsigned role = 0; role < 3; ++role)
            joiner.submit(party(selected, round, role));
    joiner.submit(std::move(continuation));
    const auto complete = joiner.finish().public_receipt();
    assert(complete.opaque_closure_authority_identity ==
           expected.opaque_closure_authority_identity);
    assert(complete.streams == expected.streams);
}

TrialCaptureCompletionAuthority capture(const RunBinding& selected) {
    TrialCaptureJoiner joiner(selected, parent_manifest(selected));
    for (unsigned round = 1; round <= 2; ++round)
        for (unsigned role = 0; role < 3; ++role)
            joiner.submit(party(selected, round, role));
    joiner.submit(producer(selected));
    return joiner.finish();
}

void incomplete_capture_join_refuses() {
    const auto selected = binding(Classification::TransparentBaseline, 0x30);
    TrialCaptureJoiner joiner(selected, parent_manifest(selected));
    for (unsigned round = 1; round <= 2; ++round)
        for (unsigned role = 0; role < 3; ++role)
            joiner.submit(party(selected, round, role));
    bool refused = false;
    try {
        (void)joiner.finish();
    } catch (const Refused&) {
        refused = true;
    }
    assert(refused);
}

void complete_capture_joins_exact_parent_observations() {
    const auto selected = binding(Classification::TransparentBaseline, 0x30);
    TrialCaptureJoiner joiner(selected, parent_manifest(selected));
    for (unsigned round = 1; round <= 2; ++round)
        for (unsigned role = 0; role < 3; ++role)
            joiner.submit(party(selected, round, role));
    joiner.submit(producer(selected));
    auto complete = joiner.finish();
    const auto& receipt = complete.public_receipt();
    assert(receipt.binding == selected);
    assert(receipt.party_child_exit[0][0] == digest(0x43));
    assert(receipt.party_egress[1][2] == digest(0x82));
    assert(receipt.party_proof[1][2] == digest(0x92));
    assert(receipt.projections == selected.projections);
    assert(receipt.opaque_closure_authority_identity == digest(0xa9));
    assert(receipt.construction_policy ==
           ConstructionPolicy::ExplicitOwnerPublicEffects);
    assert(receipt.construction_classification_receipt == digest(0xa8));
    assert(receipt.stream_count == 10);
    assert(receipt.streams[0].fixed_fd == 20);
    assert(receipt.streams[9].fixed_fd == 29);
    assert(receipt.streams[7].child_exit_identity == digest(0x88));
    assert(receipt.streams[7].root_closed);
    assert(receipt.completion_identity != Digest{});
}

void disagreeing_party_head_refuses_immediately() {
    const auto selected = binding(Classification::TransparentBaseline, 0x30);
    TrialCaptureJoiner joiner(selected, parent_manifest(selected));
    joiner.submit(party(selected, 1, 0));
    auto changed = party(selected, 1, 1).public_receipt();
    changed.accepted_head = digest(0xdd);
    bool refused = false;
    try {
        joiner.submit(PartyCompletionAuthority::test_only_mint(changed));
    } catch (const Refused&) {
        refused = true;
    }
    assert(refused);
}

void capture_replay_wrong_role_run_and_classification_refuse() {
    const auto baseline = binding(Classification::TransparentBaseline, 0x30);
    const auto other = binding(Classification::TransparentBaseline, 0x50);

    expect_refused([&] {
        auto wrong_role = party(baseline, 1, 0).public_receipt();
        wrong_role.role = 3;
        (void)PartyCompletionAuthority::test_only_mint(wrong_role);
    });

    TrialCaptureJoiner mixed(baseline, parent_manifest(baseline));
    expect_refused([&] { mixed.submit(party(other, 1, 0)); });
    expect_refused([&] { (void)mixed.finish(); });

    TrialCaptureJoiner replayed(baseline, parent_manifest(baseline));
    auto once = party(baseline, 1, 0);
    replayed.submit(std::move(once));
    expect_refused([&] { replayed.submit(std::move(once)); });
    expect_refused([&] { (void)replayed.finish(); });

    expect_refused([&] {
        auto wrong_policy = producer(baseline).public_receipt();
        wrong_policy.construction_policy =
            ConstructionPolicy::SecretPermutationIndependent;
        (void)ProducerClosureAuthority::test_only_mint(
            wrong_policy, producer_evidence());
    });
}

void exact_stream_and_manifest_tampering_refuses() {
    const auto selected = binding(Classification::HiddenCandidate, 0x60);
    expect_refused([&] {
        auto wrong_fd = producer(selected).public_receipt();
        wrong_fd.streams[4].fixed_fd = 29;
        (void)ProducerClosureAuthority::test_only_mint(
            wrong_fd, producer_evidence());
    });
    expect_refused([&] {
        auto missing_end = producer_evidence();
        missing_end.streams[4].end_frame_identity = {};
        (void)ProducerClosureAuthority::test_only_mint(
            producer(selected).public_receipt(), missing_end);
    });
    expect_refused([&] {
        auto missing_eof = producer_evidence();
        missing_eof.streams[4].eof_identity = {};
        (void)ProducerClosureAuthority::test_only_mint(
            producer(selected).public_receipt(), missing_eof);
    });
    expect_refused([&] {
        auto wrong_component = producer(selected).public_receipt();
        wrong_component.streams[4].manifest_component =
            ManifestComponent::TerminalCapture;
        (void)ProducerClosureAuthority::test_only_mint(
            wrong_component, producer_evidence());
    });
    expect_refused([&] {
        auto wrong_source = producer(selected).public_receipt();
        wrong_source.streams[4].source_identity = digest(0xee);
        (void)ProducerClosureAuthority::test_only_mint(
            wrong_source, producer_evidence());
    });
    expect_refused([&] {
        auto swapped_roles = producer(selected).public_receipt();
        const auto corrupt = swapped_roles.streams[3];
        swapped_roles.streams[3].manifest_component =
            swapped_roles.streams[4].manifest_component;
        swapped_roles.streams[3].source_identity =
            swapped_roles.streams[4].source_identity;
        swapped_roles.streams[3].build_identity =
            swapped_roles.streams[4].build_identity;
        swapped_roles.streams[3].runtime_identity =
            swapped_roles.streams[4].runtime_identity;
        swapped_roles.streams[3].launcher_identity =
            swapped_roles.streams[4].launcher_identity;
        swapped_roles.streams[4].manifest_component =
            corrupt.manifest_component;
        swapped_roles.streams[4].source_identity = corrupt.source_identity;
        swapped_roles.streams[4].build_identity = corrupt.build_identity;
        swapped_roles.streams[4].runtime_identity = corrupt.runtime_identity;
        swapped_roles.streams[4].launcher_identity =
            corrupt.launcher_identity;
        (void)ProducerClosureAuthority::test_only_mint(
            swapped_roles, producer_evidence());
    });
    expect_refused([&] {
        auto wrong_producer = producer(selected).public_receipt();
        wrong_producer.producer_worker.runtime_identity = digest(0xee);
        (void)ProducerClosureAuthority::test_only_mint(
            wrong_producer, producer_evidence());
    });
    expect_refused([&] {
        auto changed = selected;
        changed.finite_manifest.entries[0].source_identity = digest(0xee);
        TrialCaptureJoiner joiner(changed, parent_manifest(changed));
        (void)joiner;
    });
    expect_refused([&] {
        auto changed = selected;
        changed.capture_runtime = digest(0xee);
        TrialCaptureJoiner joiner(changed, parent_manifest(changed));
        (void)joiner;
    });
    expect_refused([&] {
        auto changed = selected;
        changed.observer_worker.launcher_identity = digest(0xee);
        TrialCaptureJoiner joiner(changed, parent_manifest(changed));
        (void)joiner;
    });
}

void parent_manifest_capability_is_exact_and_one_shot() {
    const auto selected = binding(Classification::HiddenCandidate, 0x60);
    auto one_shot = parent_manifest(selected);
    TrialCaptureJoiner first(selected, std::move(one_shot));
    expect_refused([&] {
        TrialCaptureJoiner replay(selected, std::move(one_shot));
        (void)replay;
    });

    auto different = selected.finite_manifest;
    different.entries[0].assets_identity = digest(0xee);
    different.manifest_identity =
        recompute_finite_manifest_identity(different.entries);
    auto wrong = ParentManifestRecomputationAuthority::test_only_mint(
        PublicParentManifestRecomputation{
            .manifest = different,
            .parent_process_identity = digest(0xc1),
            .parent_executable_identity = digest(0xc2),
            .recomputation_receipt = different.parent_recomputation_identity,
        });
    expect_refused([&] {
        TrialCaptureJoiner mismatch(selected, std::move(wrong));
        (void)mismatch;
    });
}

void capture_duplicate_race_poison_is_fail_closed() {
    const auto selected = binding(Classification::TransparentBaseline, 0x30);
    TrialCaptureJoiner joiner(selected, parent_manifest(selected));
    std::atomic_uint accepted{};
    std::atomic_uint refused{};
    auto submit = [&] {
        try {
            joiner.submit(party(selected, 1, 0));
            ++accepted;
        } catch (const Refused&) {
            ++refused;
        }
    };
    std::thread first(submit);
    std::thread second(submit);
    first.join();
    second.join();
    assert(accepted == 1);
    assert(refused == 1);
    expect_refused([&] { (void)joiner.finish(); });
}

PublicObservationCompletion observer_completes(
        RunMeasurement& measurement, const RunBinding& selected,
        unsigned char seed) {
    auto permit = measurement.issue_observer();
    const auto public_permit = permit.public_receipt();
    const PublicObservationCompletion receipt{
        .binding = selected,
        .permit_identity = public_permit.permit_identity,
        .trial_capture_identity = public_permit.trial_capture_identity,
        .child_exit = digest(seed),
        .observation_receipt = digest(seed + 1),
        .worker = selected.observer_worker,
        .process_identity = digest(seed + 2),
    };
    auto completion =
        ObservationCompletionAuthority::test_only_mint(receipt);
    auto execution =
        std::move(permit).test_only_take_execution();
    measurement.accept_observer(
        std::move(execution), std::move(completion));
    return receipt;
}

BarrierFreezeAuthority frozen_barrier(
        const RunBinding& selected,
        const PublicObservationCompletion& observation,
        const Digest& barrier_receipt) {
    return BarrierFreezeAuthority::test_only_mint(PublicBarrierFreeze{
        .binding = selected,
        .trial_capture_identity = observation.trial_capture_identity,
        .observation_receipt = observation.observation_receipt,
        .barrier_receipt = barrier_receipt,
        .outer_parent_process = selected.outer_parent_process,
        .outer_parent_executable = selected.outer_parent_executable,
        .manifest_recomputation_receipt =
            selected.finite_manifest.parent_recomputation_identity,
    });
}

void issue_candidate_global_release(
        RunMeasurement& measurement, const RunBinding& selected) {
    if (selected.classification != Classification::HiddenCandidate) return;
    auto release =
        measurement.issue_candidate_truth_barrier_release();
    assert(release.public_receipt().binding == selected);
}

void truth_before_barrier_partial_duplicate_and_wrong_owner_refuse() {
    const auto selected = binding(Classification::HiddenCandidate, 0x60);
    {
        RunMeasurement measurement(capture(selected));
        observer_completes(measurement, selected, 0x80);
        expect_refused([&] { (void)measurement.issue_score(0); });
    }
    {
        RunMeasurement measurement(capture(selected));
        const auto observation = observer_completes(
            measurement, selected, 0x83);
        measurement.freeze_barrier(
            frozen_barrier(selected, observation, digest(0x86)));
        issue_candidate_global_release(measurement, selected);
        (void)measurement.issue_score(0);
        expect_refused([&] { (void)measurement.issue_aggregate(); });
    }
    {
        RunMeasurement measurement(capture(selected));
        const auto observation = observer_completes(
            measurement, selected, 0x89);
        measurement.freeze_barrier(
            frozen_barrier(selected, observation, digest(0x8c)));
        issue_candidate_global_release(measurement, selected);
        (void)measurement.issue_score(0);
        expect_refused([&] { (void)measurement.issue_score(0); });
    }
    {
        RunMeasurement measurement(capture(selected));
        const auto observation = observer_completes(
            measurement, selected, 0x90);
        measurement.freeze_barrier(
            frozen_barrier(selected, observation, digest(0x93)));
        issue_candidate_global_release(measurement, selected);
        auto permit = measurement.issue_score(0);
        const auto public_permit = permit.public_receipt();
        auto wrong_owner = OwnerScoreCompletionAuthority::test_only_mint(
            PublicOwnerScoreCompletion{
                .binding = selected,
                .owner = 1,
                .permit_identity = public_permit.permit_identity,
                .barrier = public_permit.barrier,
                .child_exit = digest(0x94),
                .score_receipt = digest(0x95),
                .capsule_seal = digest(0x96),
                .worker = selected.score_worker,
                .process_identity = digest(0x97),
            });
        expect_refused([&] {
            measurement.accept_score(execution_permit(std::move(permit)),
                                     std::move(wrong_owner));
        });
    }
}

void barrier_capability_is_exact_and_one_shot() {
    const auto selected = binding(Classification::HiddenCandidate, 0x60);
    {
        RunMeasurement measurement(capture(selected));
        const auto observation = observer_completes(
            measurement, selected, 0x98);
        auto wrong = observation;
        wrong.observation_receipt = digest(0xee);
        expect_refused([&] {
            measurement.freeze_barrier(
                frozen_barrier(selected, wrong, digest(0x9b)));
        });
    }
    {
        RunMeasurement measurement(capture(selected));
        const auto observation = observer_completes(
            measurement, selected, 0x9c);
        auto barrier = frozen_barrier(selected, observation, digest(0x9f));
        measurement.freeze_barrier(std::move(barrier));
        expect_refused([&] {
            measurement.freeze_barrier(std::move(barrier));
        });
    }
}

void candidate_global_truth_release_is_postfreeze_and_one_shot() {
    const auto candidate = binding(
        Classification::HiddenCandidate, 0x60);
    {
        RunMeasurement measurement(capture(candidate));
        expect_refused([&] {
            (void)measurement.issue_candidate_truth_barrier_release();
        });
    }
    {
        RunMeasurement measurement(capture(candidate));
        const auto observation = observer_completes(
            measurement, candidate, 0x9d);
        measurement.freeze_barrier(frozen_barrier(
            candidate, observation, digest(0xa0)));
        expect_refused([&] { (void)measurement.issue_score(0); });
    }
    {
        RunMeasurement measurement(capture(candidate));
        const auto observation = observer_completes(
            measurement, candidate, 0xa1);
        measurement.freeze_barrier(frozen_barrier(
            candidate, observation, digest(0xa4)));
        auto release =
            measurement.issue_candidate_truth_barrier_release();
        const auto& receipt = release.public_receipt();
        assert(receipt.binding == candidate);
        assert(receipt.trial_capture_identity ==
               observation.trial_capture_identity);
        assert(receipt.observation_receipt ==
               observation.observation_receipt);
        assert(receipt.barrier == digest(0xa4));
        assert(receipt.release_identity != Digest{});
        expect_refused([&] {
            (void)measurement.issue_candidate_truth_barrier_release();
        });
    }
    {
        const auto baseline = binding(
            Classification::TransparentBaseline, 0x30);
        RunMeasurement measurement(capture(baseline));
        const auto observation = observer_completes(
            measurement, baseline, 0xa5);
        measurement.freeze_barrier(frozen_barrier(
            baseline, observation, digest(0xa8)));
        expect_refused([&] {
            (void)measurement.issue_candidate_truth_barrier_release();
        });
    }
}

void post_barrier_truth_release_split_is_exact_and_one_shot() {
    const auto selected = binding(Classification::HiddenCandidate, 0x60);
    RunMeasurement measurement(capture(selected));
    const auto observation = observer_completes(
        measurement, selected, 0x9d);
    measurement.freeze_barrier(
        frozen_barrier(selected, observation, digest(0xa0)));
    issue_candidate_global_release(measurement, selected);
    auto original = measurement.issue_score(2);
    const auto original_receipt = original.public_receipt();
    auto split = std::move(original).split_for_truth_release();
    auto scorer = split.take_execution_permit();
    auto release = split.take_truth_release_permit();
    const auto release_receipt = release.public_receipt();
    assert(release_receipt.binding == selected);
    assert(release_receipt.owner == 2);
    assert(release_receipt.trial_capture_identity ==
           original_receipt.trial_capture_identity);
    assert(release_receipt.observation_receipt ==
           original_receipt.observation_receipt);
    assert(release_receipt.barrier == original_receipt.barrier);
    assert(release_receipt.score_permit_identity ==
           original_receipt.permit_identity);
    assert(release_receipt.release_identity != Digest{});
    assert(release_receipt.binding.round_capture_plans ==
           selected.round_capture_plans);

    expect_refused([&] {
        (void)std::move(original).split_for_truth_release();
    });
    expect_refused([&] { (void)split.take_execution_permit(); });
    expect_refused([&] { (void)split.take_truth_release_permit(); });

    auto completion = OwnerScoreCompletionAuthority::test_only_mint(
        PublicOwnerScoreCompletion{
            .binding = selected,
            .owner = 2,
            .permit_identity = original_receipt.permit_identity,
            .barrier = original_receipt.barrier,
            .child_exit = digest(0xa1),
            .score_receipt = digest(0xa2),
            .capsule_seal = digest(0xa3),
            .worker = selected.score_worker,
            .process_identity = digest(0xa4),
        });
    measurement.accept_score(std::move(scorer), std::move(completion));
}

void capture_plan_lineage_is_required_and_ordered() {
    auto zero = binding(Classification::HiddenCandidate, 0x60);
    zero.round_capture_plans[0] = Digest{};
    expect_refused([&] {
        TrialCaptureJoiner joiner(zero, parent_manifest(zero));
        (void)joiner;
    });
    auto reused = binding(Classification::HiddenCandidate, 0x60);
    reused.round_capture_plans[1] = reused.round_capture_plans[0];
    expect_refused([&] {
        TrialCaptureJoiner joiner(reused, parent_manifest(reused));
        (void)joiner;
    });
    const auto selected = binding(
        Classification::HiddenCandidate, 0x60);
    auto swapped = selected;
    std::swap(swapped.round_capture_plans[0],
              swapped.round_capture_plans[1]);
    TrialCaptureJoiner joiner(selected, parent_manifest(selected));
    expect_refused([&] {
        joiner.submit(producer(swapped));
    });
}

void score_duplicate_race_poison_is_fail_closed() {
    const auto selected = binding(Classification::HiddenCandidate, 0x60);
    RunMeasurement measurement(capture(selected));
    const auto observation = observer_completes(
        measurement, selected, 0xa0);
    measurement.freeze_barrier(
        frozen_barrier(selected, observation, digest(0xa3)));
    issue_candidate_global_release(measurement, selected);
    std::atomic_uint accepted{};
    std::atomic_uint refused{};
    auto issue = [&] {
        try {
            auto permit = measurement.issue_score(0);
            (void)permit;
            ++accepted;
        } catch (const Refused&) {
            ++refused;
        }
    };
    std::thread first(issue);
    std::thread second(issue);
    first.join();
    second.join();
    assert(accepted == 1);
    assert(refused == 1);
    expect_refused([&] { (void)measurement.issue_score(1); });
}

void consumed_score_permit_replay_refuses() {
    const auto selected = binding(Classification::HiddenCandidate, 0x60);
    RunMeasurement measurement(capture(selected));
    const auto observation = observer_completes(
        measurement, selected, 0xa8);
    measurement.freeze_barrier(
        frozen_barrier(selected, observation, digest(0xab)));
    issue_candidate_global_release(measurement, selected);
    auto permit = measurement.issue_score(0);
    const auto public_permit = permit.public_receipt();
    auto execution = execution_permit(std::move(permit));
    const PublicOwnerScoreCompletion receipt{
        .binding = selected,
        .owner = 0,
        .permit_identity = public_permit.permit_identity,
        .barrier = public_permit.barrier,
        .child_exit = digest(0xac),
        .score_receipt = digest(0xad),
        .capsule_seal = digest(0xae),
        .worker = selected.score_worker,
        .process_identity = digest(0xaf),
    };
    auto first = OwnerScoreCompletionAuthority::test_only_mint(receipt);
    measurement.accept_score(std::move(execution), std::move(first));
    auto replay = OwnerScoreCompletionAuthority::test_only_mint(receipt);
    expect_refused([&] {
        measurement.accept_score(std::move(execution), std::move(replay));
    });
}

enum class ReusedScoreIdentity {
    ChildExit,
    ScoreReceipt,
    CapsuleSeal,
    Process,
};

void aggregate_refuses_reused_owner_identity(
        ReusedScoreIdentity reused) {
    const auto selected = binding(Classification::HiddenCandidate, 0x60);
    RunMeasurement measurement(capture(selected));
    const auto observation = observer_completes(
        measurement, selected, 0xb0);
    measurement.freeze_barrier(
        frozen_barrier(selected, observation, digest(0xb3)));
    issue_candidate_global_release(measurement, selected);
    for (unsigned owner = 0; owner < 3; ++owner) {
        auto permit = measurement.issue_score(owner);
        const auto public_permit = permit.public_receipt();
        PublicOwnerScoreCompletion receipt{
            .binding = selected,
            .owner = owner,
            .permit_identity = public_permit.permit_identity,
            .barrier = public_permit.barrier,
            .child_exit = digest(
                static_cast<unsigned char>(0xb4 + owner)),
            .score_receipt = digest(
                static_cast<unsigned char>(0xb7 + owner)),
            .capsule_seal = digest(
                static_cast<unsigned char>(0xba + owner)),
            .worker = selected.score_worker,
            .process_identity = digest(
                static_cast<unsigned char>(0xbd + owner)),
        };
        switch (reused) {
        case ReusedScoreIdentity::ChildExit:
            receipt.child_exit = digest(0xc0);
            break;
        case ReusedScoreIdentity::ScoreReceipt:
            receipt.score_receipt = digest(0xc1);
            break;
        case ReusedScoreIdentity::CapsuleSeal:
            receipt.capsule_seal = digest(0xc2);
            break;
        case ReusedScoreIdentity::Process:
            receipt.process_identity = digest(0xc3);
            break;
        }
        auto completion = OwnerScoreCompletionAuthority::test_only_mint(
            receipt);
        measurement.accept_score(execution_permit(std::move(permit)),
                                 std::move(completion));
    }
    expect_refused([&] { (void)measurement.issue_aggregate(); });
}

void aggregate_requires_three_distinct_owner_completions() {
    aggregate_refuses_reused_owner_identity(
        ReusedScoreIdentity::ChildExit);
    aggregate_refuses_reused_owner_identity(
        ReusedScoreIdentity::ScoreReceipt);
    aggregate_refuses_reused_owner_identity(
        ReusedScoreIdentity::CapsuleSeal);
    aggregate_refuses_reused_owner_identity(
        ReusedScoreIdentity::Process);
}

RunAggregateCompletionAuthority measured_run(
        const RunBinding& selected, AggregateOutcome outcome,
        unsigned char seed) {
    RunMeasurement measurement(capture(selected));
    auto observer_permit = measurement.issue_observer();
    const auto observer_public = observer_permit.public_receipt();
    auto observation = ObservationCompletionAuthority::test_only_mint(
        PublicObservationCompletion{
            .binding = selected,
            .permit_identity = observer_public.permit_identity,
            .trial_capture_identity = observer_public.trial_capture_identity,
            .child_exit = digest(seed),
            .observation_receipt = digest(seed + 1),
            .worker = selected.observer_worker,
            .process_identity = digest(seed + 14),
        });
    auto observer_execution =
        std::move(observer_permit).test_only_take_execution();
    measurement.accept_observer(std::move(observer_execution),
                                std::move(observation));
    measurement.freeze_barrier(BarrierFreezeAuthority::test_only_mint(
        PublicBarrierFreeze{
            .binding = selected,
            .trial_capture_identity = observer_public.trial_capture_identity,
            .observation_receipt = digest(seed + 1),
            .barrier_receipt = digest(seed + 2),
            .outer_parent_process = selected.outer_parent_process,
            .outer_parent_executable = selected.outer_parent_executable,
            .manifest_recomputation_receipt =
                selected.finite_manifest.parent_recomputation_identity,
        }));
    issue_candidate_global_release(measurement, selected);
    for (unsigned owner = 0; owner < 3; ++owner) {
        auto permit = measurement.issue_score(owner);
        const auto score_public = permit.public_receipt();
        auto score = OwnerScoreCompletionAuthority::test_only_mint(
            PublicOwnerScoreCompletion{
                .binding = selected,
                .owner = owner,
                .permit_identity = score_public.permit_identity,
                .barrier = digest(seed + 2),
                .child_exit = digest(
                    static_cast<unsigned char>(seed + 3 + owner)),
                .score_receipt = digest(
                    static_cast<unsigned char>(seed + 6 + owner)),
                .capsule_seal = digest(
                    static_cast<unsigned char>(seed + 9 + owner)),
                .worker = selected.score_worker,
                .process_identity = digest(
                    static_cast<unsigned char>(seed + 15 + owner)),
            });
        measurement.accept_score(execution_permit(std::move(permit)),
                                 std::move(score));
    }
    auto aggregate_permit = measurement.issue_aggregate();
    const auto aggregate_public = aggregate_permit.public_receipt();
    auto child = AggregateCompletionAuthority::test_only_mint(
        PublicAggregateCompletion{
            .binding = selected,
            .permit_identity = aggregate_public.permit_identity,
            .barrier = digest(seed + 2),
            .child_exit = digest(seed + 12),
            .aggregate_receipt = digest(seed + 13),
            .outcome = outcome,
            .worker = selected.aggregate_worker,
            .process_identity = digest(seed + 19),
        });
    return measurement.accept_aggregate(
        std::move(aggregate_permit), std::move(child));
}

void ordered_measurement_mints_one_run_aggregate() {
    const auto selected = binding(Classification::HiddenCandidate, 0xb0);
    auto completed = measured_run(
        selected, AggregateOutcome::CandidatePass, 0xc0);
    const auto& receipt = completed.public_receipt();
    assert(receipt.binding == selected);
    assert(receipt.barrier == digest(0xc2));
    assert(receipt.observation_receipt == digest(0xc1));
    const std::array<Digest, 3> expected_scores{
        digest(0xc6), digest(0xc7), digest(0xc8)};
    assert(receipt.score_receipts == expected_scores);
    assert(receipt.aggregate_receipt == digest(0xcd));
    assert(receipt.outcome == AggregateOutcome::CandidatePass);
    assert(receipt.completion_identity != Digest{});
}

void comparison_mints_bounded_batch_privacy_pass() {
    const auto baseline_binding =
        binding(Classification::TransparentBaseline, 0x40);
    const auto candidate_binding =
        binding(Classification::HiddenCandidate, 0x70);
    auto baseline = measured_run(
        baseline_binding, AggregateOutcome::BaselineControlDetected, 0x90);
    auto candidate = measured_run(
        candidate_binding, AggregateOutcome::CandidatePass, 0xb0);
    auto selection = ComparisonSelectionAuthority::test_only_mint(
        PublicComparisonSelection{
            .comparison_selection = baseline_binding.comparison_selection,
            .selection_identity = digest(0x2a),
            .method = baseline_binding.method,
            .workload = baseline_binding.workload,
            .source_closure = baseline_binding.source_closure,
            .runtime = baseline_binding.runtime,
            .finite_manifest = baseline_binding.finite_manifest,
            .comparison_worker =
                worker(baseline_binding.finite_manifest.entries.at(9)),
            .outer_parent_process = baseline_binding.outer_parent_process,
            .outer_parent_executable =
                baseline_binding.outer_parent_executable,
            .manifest_recomputation_receipt = baseline_binding.finite_manifest
                .parent_recomputation_identity,
            .baseline_run = baseline_binding.run_selection,
            .candidate_run = candidate_binding.run_selection,
        });
    ComparisonMeasurement comparison(
        std::move(selection), std::move(baseline), std::move(candidate));
    auto permit = comparison.issue_owner_comparison();
    const auto public_permit = permit.public_receipt();
    auto completion = OwnerComparisonCompletionAuthority::test_only_mint(
        PublicOwnerComparisonCompletion{
            .comparison_selection = baseline_binding.comparison_selection,
            .permit_identity = public_permit.permit_identity,
            .baseline_aggregate = public_permit.baseline_aggregate,
            .candidate_aggregate = public_permit.candidate_aggregate,
            .child_exit = digest(0x2b),
            .comparison_receipt = digest(0x2c),
            .outcome = OwnerComparisonOutcome::NonRegressionPass,
            .worker = public_permit.selection.comparison_worker,
            .process_identity = digest(0x2d),
        });
    auto pass = comparison.accept_owner_comparison(
        std::move(permit), std::move(completion));
    const auto& receipt = pass.public_receipt();
    assert(receipt.scope == PrivacyScope::BatchPaymentPreNetworkOnly);
    assert(receipt.comparison_selection ==
           baseline_binding.comparison_selection);
    assert(receipt.owner_comparison_receipt == digest(0x2c));
    assert(receipt.pass_identity != Digest{});
    assert(receipt.finite_manifest_identity ==
           baseline_binding.finite_manifest.manifest_identity);
    assert(receipt.candidate_trial == candidate_binding.trial);
    assert(receipt.candidate_trial != baseline_binding.trial);
    assert(receipt.candidate_projections == candidate_binding.projections);
    assert((receipt.candidate_projections !=
            std::array<Digest, 2>{candidate_binding.projections[1],
                                  candidate_binding.projections[0]}));

    auto moved = std::move(pass);
    expect_refused([&] {
        (void)pass.consume_for_testnet_activation();
    });
    const auto activation_receipt =
        moved.consume_for_testnet_activation();
    assert(activation_receipt.pass_identity == receipt.pass_identity);
    assert(activation_receipt.candidate_trial == candidate_binding.trial);
    assert(activation_receipt.candidate_projections ==
           candidate_binding.projections);
    expect_refused([&] {
        (void)moved.consume_for_testnet_activation();
    });
}

PublicComparisonSelection selection_for(const RunBinding& baseline,
                                        const RunBinding& candidate) {
    return PublicComparisonSelection{
        .comparison_selection = baseline.comparison_selection,
        .selection_identity = digest(0x2a),
        .method = baseline.method,
        .workload = baseline.workload,
        .source_closure = baseline.source_closure,
        .runtime = baseline.runtime,
        .finite_manifest = baseline.finite_manifest,
        .comparison_worker = worker(baseline.finite_manifest.entries.at(9)),
        .outer_parent_process = baseline.outer_parent_process,
        .outer_parent_executable = baseline.outer_parent_executable,
        .manifest_recomputation_receipt =
            baseline.finite_manifest.parent_recomputation_identity,
        .baseline_run = baseline.run_selection,
        .candidate_run = candidate.run_selection,
    };
}

void cross_run_mix_and_nonpass_comparison_refuse() {
    const auto baseline_binding =
        binding(Classification::TransparentBaseline, 0x40);
    const auto candidate_binding =
        binding(Classification::HiddenCandidate, 0x70);
    const auto other_candidate_binding =
        binding(Classification::HiddenCandidate, 0x78);
    {
        auto baseline = measured_run(
            baseline_binding, AggregateOutcome::BaselineControlDetected, 0x90);
        auto other_candidate = measured_run(
            other_candidate_binding, AggregateOutcome::CandidatePass, 0xb0);
        auto selection = ComparisonSelectionAuthority::test_only_mint(
            selection_for(baseline_binding, candidate_binding));
        expect_refused([&] {
            ComparisonMeasurement comparison(
                std::move(selection), std::move(baseline),
                std::move(other_candidate));
            (void)comparison;
        });
    }
    {
        auto baseline = measured_run(
            baseline_binding, AggregateOutcome::BaselineControlDetected, 0x92);
        auto candidate = measured_run(
            candidate_binding, AggregateOutcome::CandidatePass, 0xb2);
        auto selection = ComparisonSelectionAuthority::test_only_mint(
            selection_for(baseline_binding, candidate_binding));
        ComparisonMeasurement comparison(
            std::move(selection), std::move(baseline), std::move(candidate));
        auto permit = comparison.issue_owner_comparison();
        const auto public_permit = permit.public_receipt();
        auto failed = OwnerComparisonCompletionAuthority::test_only_mint(
            PublicOwnerComparisonCompletion{
                .comparison_selection =
                    baseline_binding.comparison_selection,
                .permit_identity = public_permit.permit_identity,
                .baseline_aggregate = public_permit.baseline_aggregate,
                .candidate_aggregate = public_permit.candidate_aggregate,
                .child_exit = digest(0x2b),
                .comparison_receipt = digest(0x2c),
                .outcome = OwnerComparisonOutcome::Fail,
                .worker = public_permit.selection.comparison_worker,
                .process_identity = digest(0x2d),
            });
        expect_refused([&] {
            (void)comparison.accept_owner_comparison(
                std::move(permit), std::move(failed));
        });
    }
    {
        auto baseline = measured_run(
            baseline_binding, AggregateOutcome::BaselineControlDetected, 0x93);
        auto candidate = measured_run(
            candidate_binding, AggregateOutcome::CandidatePass, 0xb3);
        auto selection = ComparisonSelectionAuthority::test_only_mint(
            selection_for(baseline_binding, candidate_binding));
        ComparisonMeasurement comparison(
            std::move(selection), std::move(baseline), std::move(candidate));
        auto permit = comparison.issue_owner_comparison();
        const auto public_permit = permit.public_receipt();
        auto swapped = OwnerComparisonCompletionAuthority::test_only_mint(
            PublicOwnerComparisonCompletion{
                .comparison_selection =
                    baseline_binding.comparison_selection,
                .permit_identity = public_permit.permit_identity,
                .baseline_aggregate = public_permit.candidate_aggregate,
                .candidate_aggregate = public_permit.baseline_aggregate,
                .child_exit = digest(0x2e),
                .comparison_receipt = digest(0x2f),
                .outcome = OwnerComparisonOutcome::NonRegressionPass,
                .worker = public_permit.selection.comparison_worker,
                .process_identity = digest(0x30),
            });
        expect_refused([&] {
            (void)comparison.accept_owner_comparison(
                std::move(permit), std::move(swapped));
        });
    }
    {
        auto other_parent_candidate = candidate_binding;
        other_parent_candidate.outer_parent_process = digest(0xef);
        auto baseline = measured_run(
            baseline_binding, AggregateOutcome::BaselineControlDetected, 0x94);
        auto candidate = measured_run(
            other_parent_candidate, AggregateOutcome::CandidatePass, 0xb4);
        auto selection = ComparisonSelectionAuthority::test_only_mint(
            selection_for(baseline_binding, candidate_binding));
        expect_refused([&] {
            ComparisonMeasurement comparison(
                std::move(selection), std::move(baseline),
                std::move(candidate));
            (void)comparison;
        });
    }
}

void comparison_worker_must_be_manifest_bound() {
    const auto baseline =
        binding(Classification::TransparentBaseline, 0x40);
    const auto candidate = binding(Classification::HiddenCandidate, 0x70);
    auto chosen = selection_for(baseline, candidate);
    chosen.comparison_worker.runtime_identity = digest(0xee);
    expect_refused([&] {
        (void)ComparisonSelectionAuthority::test_only_mint(chosen);
    });
}

void classification_outcome_mismatch_refuses() {
    const auto baseline =
        binding(Classification::TransparentBaseline, 0x40);
    expect_refused([&] {
        (void)AggregateCompletionAuthority::test_only_mint(
            PublicAggregateCompletion{
                .binding = baseline,
                .permit_identity = digest(0xb0),
                .barrier = digest(0xb1),
                .child_exit = digest(0xb2),
                .aggregate_receipt = digest(0xb3),
                .outcome = AggregateOutcome::CandidatePass,
                .worker = baseline.aggregate_worker,
                .process_identity = digest(0xb4),
            });
    });
}

void every_execution_status_stays_false() {
    static_assert(!kSourceStatus.finite_manifest_parent_tooling);
    static_assert(!kSourceStatus.party_completion_adapter);
    static_assert(!kSourceStatus.producer_closure_adapter);
    static_assert(!kSourceStatus.registered_capture_supervisor);
    static_assert(!kSourceStatus.observation_child_adapter);
    static_assert(!kSourceStatus.barrier_freeze_adapter);
    static_assert(!kSourceStatus.owner_score_child_adapter);
    static_assert(!kSourceStatus.aggregate_child_adapter);
    static_assert(!kSourceStatus.owner_comparison_child_adapter);
    static_assert(!kSourceStatus.run_measurement_supervisor);
    static_assert(!kSourceStatus.comparison_supervisor);
    static_assert(!kSourceStatus.pre_network_safety_authority);
    static_assert(!kSourceStatus.accepted_payment_terminal_authority);
    static_assert(!kSourceStatus.terminal_exit_privacy_authority);
    static_assert(!kSourceStatus.activation_supervisor);
    static_assert(!kSourceStatus.configured);
    static_assert(!kSourceStatus.launch_enabled);
    static_assert(!kSourceStatus.actual_privacy_pass);
}

} // namespace

int main() {
    producer_native_terminal_transfer_is_exact_and_one_shot();
    incomplete_capture_join_refuses();
    complete_capture_joins_exact_parent_observations();
    disagreeing_party_head_refuses_immediately();
    capture_replay_wrong_role_run_and_classification_refuse();
    exact_stream_and_manifest_tampering_refuses();
    parent_manifest_capability_is_exact_and_one_shot();
    capture_duplicate_race_poison_is_fail_closed();
    truth_before_barrier_partial_duplicate_and_wrong_owner_refuse();
    barrier_capability_is_exact_and_one_shot();
    candidate_global_truth_release_is_postfreeze_and_one_shot();
    post_barrier_truth_release_split_is_exact_and_one_shot();
    capture_plan_lineage_is_required_and_ordered();
    score_duplicate_race_poison_is_fail_closed();
    consumed_score_permit_replay_refuses();
    aggregate_requires_three_distinct_owner_completions();
    ordered_measurement_mints_one_run_aggregate();
    comparison_mints_bounded_batch_privacy_pass();
    cross_run_mix_and_nonpass_comparison_refuse();
    comparison_worker_must_be_manifest_bound();
    classification_outcome_mismatch_refuses();
    every_execution_status_stays_false();
}
