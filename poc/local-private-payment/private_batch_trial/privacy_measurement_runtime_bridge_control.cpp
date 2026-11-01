#include "privacy_measurement_runtime_bridge.hpp"
#include "privacy_native_empirical_result_test_fixture.hpp"
#include "privacy_measurement_child_output_authority.hpp"
#include "privacy_measurement_sha256.hpp"

#include <cassert>
#include <concepts>
#include <sys/syscall.h>
#include <unistd.h>

using namespace kpb::measurement;
using namespace kpb::measurement::runtime_bridge;
namespace empirical_fixture =
    kpb::measurement::empirical_result::test_fixture;

namespace {

template<class Function>
void expect_refused(Function&& function) {
    bool refused = false;
    try { function(); } catch (const Refused&) { refused = true; }
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

WorkerBinding worker() {
    return {
        .source_identity = digest(1),
        .build_identity = digest(2),
        .runtime_identity = digest(3),
        .assets_identity = digest(4),
        .pinned_executable_identity = digest(5),
        .launcher_identity = digest(6),
    };
}

WorkerBinding worker(const ManifestEntry& value) {
    return {
        .source_identity = value.source_identity,
        .build_identity = value.build_identity,
        .runtime_identity = value.runtime_identity,
        .assets_identity = value.assets_identity,
        .pinned_executable_identity = value.pinned_executable_identity,
        .launcher_identity = value.launcher_identity,
    };
}

FiniteManifestBinding manifest() {
    std::array<ManifestEntry, 10> entries{};
    for (unsigned index = 0; index < entries.size(); ++index) {
        const auto seed = static_cast<unsigned char>(0x30 + 6 * index);
        entries[index] = {
            .component = static_cast<ManifestComponent>(index + 1),
            .source_identity = digest(seed),
            .build_identity = digest(seed + 1),
            .runtime_identity = digest(seed + 2),
            .assets_identity = digest(seed + 3),
            .pinned_executable_identity = digest(seed + 4),
            .launcher_identity = digest(seed + 5),
        };
    }
    return {
        .manifest_identity = recompute_finite_manifest_identity(entries),
        .parent_recomputation_identity = digest(0xa0),
        .entries = entries,
    };
}

RunBinding binding() {
    const auto selected = manifest();
    const auto& capture = selected.entries.at(1);
    return {
        .classification = Classification::HiddenCandidate,
        .comparison_selection = digest(0xb0),
        .run_selection = digest(0xb1),
        .trial = digest(0xb2),
        .attempt = digest(0xb3),
        .cohort = digest(0xb4),
        .capture = digest(0xb5),
        .method = digest(0xb6),
        .workload = digest(0xb7),
        .source_closure = digest(0xb8),
        .runtime = digest(0xb9),
        .finite_manifest = selected,
        .outer_parent_process = digest(0xba),
        .outer_parent_executable = digest(0xbb),
        .capture_source = capture.source_identity,
        .capture_build = capture.build_identity,
        .capture_runtime = capture.runtime_identity,
        .capture_launcher = capture.launcher_identity,
        .observer_worker = worker(selected.entries.at(6)),
        .score_worker = worker(selected.entries.at(7)),
        .aggregate_worker = worker(selected.entries.at(8)),
        .financial_runs = {digest(0xbc), digest(0xbd)},
        .round_attempts = {digest(0xbe), digest(0xbf)},
        .round_cohorts = {digest(0xc0), digest(0xc1)},
        .round_capture_plans = {digest(0xc4), digest(0xc5)},
        .projections = {digest(0xc2), digest(0xc3)},
    };
}

PublicObserverPermit observer_permit() {
    return {
        .binding = binding(),
        .trial_capture_identity = digest(0xc4),
        .permit_identity = digest(0xc5),
    };
}

PublicOwnerScorePermit score_permit(unsigned owner = 1) {
    return {
        .binding = binding(),
        .owner = owner,
        .trial_capture_identity = digest(0xc4),
        .observation_receipt = digest(0xc6),
        .barrier = digest(0xc7),
        .permit_identity = digest(static_cast<unsigned char>(0xc8 + owner)),
    };
}

PublicAggregatePermit aggregate_permit() {
    return {
        .binding = binding(),
        .trial_capture_identity = digest(0xc4),
        .observation_receipt = digest(0xc6),
        .barrier = digest(0xc7),
        .score_receipts = {digest(0xd1), digest(0xd2), digest(0xd3)},
        .capsule_seals = {digest(0xd4), digest(0xd5), digest(0xd6)},
        .permit_identity = digest(0xd7),
    };
}

PublicOwnerComparisonPermit comparison_permit() {
    const auto run = binding();
    return {
        .selection = {
            .comparison_selection = run.comparison_selection,
            .selection_identity = digest(0xd8),
            .method = run.method,
            .workload = run.workload,
            .source_closure = run.source_closure,
            .runtime = run.runtime,
            .finite_manifest = run.finite_manifest,
            .comparison_worker = worker(run.finite_manifest.entries.at(9)),
            .outer_parent_process = run.outer_parent_process,
            .outer_parent_executable = run.outer_parent_executable,
            .manifest_recomputation_receipt =
                run.finite_manifest.parent_recomputation_identity,
            .baseline_run = digest(0xd9),
            .candidate_run = run.run_selection,
        },
        .baseline_aggregate = digest(0xda),
        .candidate_aggregate = digest(0xdb),
        .permit_identity = digest(0xdc),
    };
}

PublicRuntimeChildCompletion valid_observer(
        const PublicObserverPermit& permit = observer_permit()) {
    PublicRuntimeChildCompletion value{
        .role = RuntimeChildRole::Observer,
        .owner = NO_OWNER,
        .permit_identity = permit.permit_identity,
        .worker = permit.binding.observer_worker,
        .outer_parent_process = permit.binding.outer_parent_process,
        .outer_parent_executable = permit.binding.outer_parent_executable,
        .transport_session = digest(10),
        .offer_identity = digest(11),
        .child_exit_identity = digest(12),
        .opaque_completion_authority_identity = digest(13),
        .opaque_capsule_authority_identity = {},
        .authenticated_pid = 4001,
        .waited_pid = 4001,
        .exit_code = 0,
        .term_signal = 0,
        .credentials_verified = true,
        .offer_acknowledged = true,
        .eof_observed = true,
        .aggregate_outcome = static_cast<AggregateOutcome>(0),
        .comparison_outcome = static_cast<OwnerComparisonOutcome>(0),
    };
    value.process_identity = recompute_process_identity(value);
    return value;
}

PublicRuntimeChildCompletion valid_score(
        const PublicOwnerScorePermit& permit = score_permit()) {
    auto value = valid_observer();
    value.role = RuntimeChildRole::OwnerScore;
    value.owner = permit.owner;
    value.permit_identity = permit.permit_identity;
    value.worker = permit.binding.score_worker;
    value.outer_parent_process = permit.binding.outer_parent_process;
    value.outer_parent_executable = permit.binding.outer_parent_executable;
    value.transport_session = digest(
        static_cast<unsigned char>(10 + permit.owner));
    value.offer_identity = digest(
        static_cast<unsigned char>(11 + permit.owner));
    value.child_exit_identity = digest(
        static_cast<unsigned char>(12 + permit.owner));
    value.opaque_completion_authority_identity = digest(
        static_cast<unsigned char>(13 + permit.owner));
    value.opaque_capsule_authority_identity = digest(
        static_cast<unsigned char>(0xd0 + permit.owner));
    value.authenticated_pid = 4001 + permit.owner;
    value.waited_pid = 4001 + permit.owner;
    value.process_identity = recompute_process_identity(value);
    return value;
}

PublicRuntimeChildCompletion valid_aggregate(
        const PublicAggregatePermit& permit = aggregate_permit()) {
    auto value = valid_observer();
    value.role = RuntimeChildRole::Aggregate;
    value.permit_identity = permit.permit_identity;
    value.worker = permit.binding.aggregate_worker;
    value.outer_parent_process = permit.binding.outer_parent_process;
    value.outer_parent_executable = permit.binding.outer_parent_executable;
    value.aggregate_outcome = AggregateOutcome::CandidatePass;
    value.process_identity = recompute_process_identity(value);
    return value;
}

PublicRuntimeChildCompletion valid_comparison(
        const PublicOwnerComparisonPermit& permit = comparison_permit()) {
    auto value = valid_observer();
    value.role = RuntimeChildRole::OwnerComparison;
    value.permit_identity = permit.permit_identity;
    value.worker = permit.selection.comparison_worker;
    value.outer_parent_process = permit.selection.outer_parent_process;
    value.outer_parent_executable = permit.selection.outer_parent_executable;
    value.comparison_outcome = OwnerComparisonOutcome::NonRegressionPass;
    value.process_identity = recompute_process_identity(value);
    return value;
}

SealedChildOutputAuthority sealed_output(
        const RunBinding& binding, RuntimeChildRole role, unsigned owner,
        const Digest& permit_identity,
        const PublicRuntimeChildCompletion& child) {
    const auto* abi = measurement_output_abi(role);
    assert(abi != nullptr);
    PrivateChildOutputOffer offer{
        .binding = binding,
        .role = role,
        .owner = owner,
        .permit_identity = permit_identity,
        .worker = role == RuntimeChildRole::Observer
            ? binding.observer_worker : binding.score_worker,
        .transport_session = child.transport_session,
        .output_authority_identity = digest(
            static_cast<unsigned char>(0xe0 +
                (owner == NO_OWNER ? 0 : owner + 1))),
        .output_abi_identity = abi->identity,
        .exact_size = abi->exact_bytes,
    };
    auto pending = MeasurementChildOutputPlane::test_only_begin(offer);
    const int fd = pending.test_only_take_child_fd();
    const auto body = test_only_measurement_output_abi_body(role, owner);
    assert(::pwrite(fd, body.data(), body.size(), 0) ==
           static_cast<ssize_t>(body.size()));
    assert(::close(fd) == 0);
    const auto content = kpb::measurement::detail::sha256(body);
    auto completion =
        AuthenticatedChildOutputCompletionAuthority::test_only_mint({
            .offer = offer,
            .content_hash = content,
            .process_identity = child.process_identity,
            .child_exit_identity = child.child_exit_identity,
            .authenticated_pid = child.authenticated_pid,
            .waited_pid = child.waited_pid,
            .exit_code = child.exit_code,
            .term_signal = child.term_signal,
            .credentials_verified = child.credentials_verified,
            .eof_observed = child.eof_observed,
        });
    return MeasurementChildOutputPlane::finish(
        std::move(pending), std::move(completion));
}

template<class Change>
void refuses(Change&& change) {
    auto value = valid_observer();
    change(value);
    bool refused = false;
    try {
        (void)ChildCompletionEvidenceAuthority::test_only_mint(value);
    } catch (const Refused&) {
        refused = true;
    }
    assert(refused);
}

void valid_evidence_is_move_only_and_one_shot() {
    static_assert(!std::default_initializable<
                  ChildCompletionEvidenceAuthority>);
    static_assert(!std::copy_constructible<
                  ChildCompletionEvidenceAuthority>);
    static_assert(!std::constructible_from<
                  ChildCompletionEvidenceAuthority,
                  PublicRuntimeChildCompletion>);

    auto authority = ChildCompletionEvidenceAuthority::test_only_mint(
        valid_observer());
    assert(authority.public_receipt().role == RuntimeChildRole::Observer);
    assert(authority.public_receipt().process_identity != Digest{});
    RuntimeCompletionBridge::test_only_consume(std::move(authority));
    bool refused = false;
    try {
        RuntimeCompletionBridge::test_only_consume(std::move(authority));
    } catch (const Refused&) {
        refused = true;
    }
    assert(refused);
}

void malformed_or_unbound_evidence_refuses() {
    refuses([](auto& value) { value.owner = 0; });
    refuses([](auto& value) { value.worker.source_identity = {}; });
    refuses([](auto& value) { value.authenticated_pid = 4002; });
    refuses([](auto& value) { value.exit_code = 1; });
    refuses([](auto& value) { value.term_signal = 9; });
    refuses([](auto& value) { value.credentials_verified = false; });
    refuses([](auto& value) { value.offer_acknowledged = false; });
    refuses([](auto& value) { value.eof_observed = false; });
    refuses([](auto& value) { value.process_identity = digest(99); });
    refuses([](auto& value) {
        value.aggregate_outcome = AggregateOutcome::CandidatePass;
        value.process_identity = recompute_process_identity(value);
    });
    refuses([](auto& value) {
        value.opaque_capsule_authority_identity = digest(98);
        value.process_identity = recompute_process_identity(value);
    });
}

void source_status_is_truthful() {
    static_assert(kRuntimeBridgeSourceStatus.evidence_authority);
    static_assert(kRuntimeBridgeSourceStatus.authenticated_child_supervisor);
    static_assert(!kRuntimeBridgeSourceStatus.registered_transport_integrated);
    static_assert(kRuntimeBridgeSourceStatus.observation_adapter);
    static_assert(kRuntimeBridgeSourceStatus.owner_score_adapter);
    static_assert(kRuntimeBridgeSourceStatus.aggregate_adapter);
    static_assert(kRuntimeBridgeSourceStatus.owner_comparison_adapter);
    static_assert(!kRuntimeBridgeSourceStatus.configured);
    static_assert(!kRuntimeBridgeSourceStatus.launch_enabled);
    static_assert(!kRuntimeBridgeSourceStatus.actual_privacy_pass);
}

void observer_adapter_preserves_the_genuine_permit() {
    const auto public_permit = observer_permit();
    auto permit =
        ObserverExecutionPermitAuthority::test_only_mint(public_permit);
    const auto evidence_value = valid_observer(public_permit);
    auto output = sealed_output(
        public_permit.binding, RuntimeChildRole::Observer, NO_OWNER,
        public_permit.permit_identity, evidence_value);
    auto evidence = ChildCompletionEvidenceAuthority::test_only_mint(
        evidence_value);
    auto completed = RuntimeCompletionBridge::observation(
        std::move(permit), std::move(evidence), std::move(output),
        empirical_fixture::exact(public_permit.binding));
    assert(completed.permit.public_receipt().permit_identity ==
           public_permit.permit_identity);
    const auto& receipt = completed.completion.public_receipt();
    assert(receipt.binding == public_permit.binding);
    assert(receipt.permit_identity == public_permit.permit_identity);
    assert(receipt.trial_capture_identity ==
           public_permit.trial_capture_identity);
    assert(receipt.child_exit == digest(12));
    assert(receipt.observation_receipt != Digest{} &&
           receipt.observation_receipt != digest(13));
    assert(receipt.worker == public_permit.binding.observer_worker);
    assert(receipt.process_identity ==
           recompute_process_identity(valid_observer(public_permit)));
}

template<class Change>
void observer_adapter_refuses(Change&& change) {
    const auto public_permit = observer_permit();
    auto permit =
        ObserverExecutionPermitAuthority::test_only_mint(public_permit);
    auto evidence_value = valid_observer(public_permit);
    change(evidence_value);
    evidence_value.process_identity = recompute_process_identity(
        evidence_value);
    auto evidence = ChildCompletionEvidenceAuthority::test_only_mint(
        evidence_value);
    auto output = sealed_output(
        public_permit.binding, RuntimeChildRole::Observer, NO_OWNER,
        public_permit.permit_identity, evidence_value);
    auto empirical = empirical_fixture::exact(public_permit.binding);
    bool refused = false;
    try {
        (void)RuntimeCompletionBridge::observation(
            std::move(permit), std::move(evidence), std::move(output),
            std::move(empirical));
    } catch (const Refused&) {
        refused = true;
    }
    assert(refused);

    auto retry_permit =
        ObserverExecutionPermitAuthority::test_only_mint(public_permit);
    auto retry_evidence = ChildCompletionEvidenceAuthority::test_only_mint(
        valid_observer(public_permit));
    expect_refused([&] {
        (void)RuntimeCompletionBridge::observation(
            std::move(retry_permit), std::move(retry_evidence),
            std::move(output), std::move(empirical));
    });
}

void observer_adapter_rejects_cross_run_or_worker_substitution() {
    observer_adapter_refuses([](auto& value) {
        value.permit_identity = digest(0xee);
    });
    observer_adapter_refuses([](auto& value) {
        value.worker = worker();
    });
    observer_adapter_refuses([](auto& value) {
        value.outer_parent_process = digest(0xed);
    });
    observer_adapter_refuses([](auto& value) {
        value.outer_parent_executable = digest(0xec);
    });
}

void observer_wrong_permit_burns_output_and_empirical_before_refusal() {
    const auto selected = observer_permit();
    auto wrong = selected;
    wrong.permit_identity = digest(0xee);
    auto permit = ObserverExecutionPermitAuthority::test_only_mint(wrong);
    const auto evidence_value = valid_observer(selected);
    auto evidence = ChildCompletionEvidenceAuthority::test_only_mint(
        evidence_value);
    auto output = sealed_output(
        selected.binding, RuntimeChildRole::Observer, NO_OWNER,
        selected.permit_identity, evidence_value);
    auto empirical = empirical_fixture::exact(selected.binding);
    expect_refused([&] {
        (void)RuntimeCompletionBridge::observation(
            std::move(permit), std::move(evidence), std::move(output),
            std::move(empirical));
    });
    auto retry_permit =
        ObserverExecutionPermitAuthority::test_only_mint(selected);
    auto retry_evidence = ChildCompletionEvidenceAuthority::test_only_mint(
        evidence_value);
    expect_refused([&] {
        (void)RuntimeCompletionBridge::observation(
            std::move(retry_permit), std::move(retry_evidence),
            std::move(output), std::move(empirical));
    });
}

void owner_score_adapter_preserves_owner_scope() {
    const auto public_permit = score_permit(1);
    auto permit = execution_permit(
        OwnerScorePermitAuthority::test_only_mint(public_permit));
    const auto evidence_value = valid_score(public_permit);
    auto output = sealed_output(
        public_permit.binding, RuntimeChildRole::OwnerScore,
        public_permit.owner, public_permit.permit_identity, evidence_value);
    auto evidence = ChildCompletionEvidenceAuthority::test_only_mint(
        evidence_value);
    auto completed = RuntimeCompletionBridge::owner_score(
        std::move(permit), std::move(evidence), std::move(output));
    assert(completed.permit.public_receipt().owner == 1);
    const auto& receipt = completed.completion.public_receipt();
    assert(receipt.binding == public_permit.binding);
    assert(receipt.owner == 1);
    assert(receipt.permit_identity == public_permit.permit_identity);
    assert(receipt.barrier == public_permit.barrier);
    assert(receipt.child_exit == digest(13));
    assert(receipt.score_receipt != Digest{} &&
           receipt.capsule_seal != Digest{} &&
           receipt.score_receipt != receipt.capsule_seal);
    assert(receipt.worker == public_permit.binding.score_worker);
}

template<class Change>
void owner_score_adapter_refuses(Change&& change) {
    const auto public_permit = score_permit(1);
    auto permit = execution_permit(
        OwnerScorePermitAuthority::test_only_mint(public_permit));
    auto evidence_value = valid_score(public_permit);
    change(evidence_value);
    evidence_value.process_identity = recompute_process_identity(
        evidence_value);
    auto evidence = ChildCompletionEvidenceAuthority::test_only_mint(
        evidence_value);
    auto output = sealed_output(
        public_permit.binding, RuntimeChildRole::OwnerScore,
        public_permit.owner, public_permit.permit_identity, evidence_value);
    bool refused = false;
    try {
        (void)RuntimeCompletionBridge::owner_score(
            std::move(permit), std::move(evidence), std::move(output));
    } catch (const Refused&) {
        refused = true;
    }
    assert(refused);
}

void owner_score_adapter_rejects_wrong_owner_permit_or_worker() {
    owner_score_adapter_refuses([](auto& value) { value.owner = 2; });
    owner_score_adapter_refuses([](auto& value) {
        value.permit_identity = digest(0xee);
    });
    owner_score_adapter_refuses([](auto& value) {
        value.worker = worker();
    });
}

void aggregate_adapter_preserves_candidate_outcome() {
    const auto public_permit = aggregate_permit();
    auto permit = AggregatePermitAuthority::test_only_mint(public_permit);
    auto evidence = ChildCompletionEvidenceAuthority::test_only_mint(
        valid_aggregate(public_permit));
    auto completed = RuntimeCompletionBridge::aggregate(
        std::move(permit), std::move(evidence));
    const auto& receipt = completed.completion.public_receipt();
    assert(receipt.binding == public_permit.binding);
    assert(receipt.permit_identity == public_permit.permit_identity);
    assert(receipt.barrier == public_permit.barrier);
    assert(receipt.aggregate_receipt == digest(13));
    assert(receipt.outcome == AggregateOutcome::CandidatePass);
    assert(receipt.worker == public_permit.binding.aggregate_worker);
}

template<class Change>
void aggregate_adapter_refuses(Change&& change) {
    const auto public_permit = aggregate_permit();
    auto permit = AggregatePermitAuthority::test_only_mint(public_permit);
    auto evidence_value = valid_aggregate(public_permit);
    change(evidence_value);
    evidence_value.process_identity = recompute_process_identity(
        evidence_value);
    auto evidence = ChildCompletionEvidenceAuthority::test_only_mint(
        evidence_value);
    bool refused = false;
    try {
        (void)RuntimeCompletionBridge::aggregate(
            std::move(permit), std::move(evidence));
    } catch (const Refused&) {
        refused = true;
    }
    assert(refused);
}

void aggregate_adapter_rejects_wrong_outcome_permit_or_worker() {
    aggregate_adapter_refuses([](auto& value) {
        value.aggregate_outcome = AggregateOutcome::BaselineControlDetected;
    });
    aggregate_adapter_refuses([](auto& value) {
        value.permit_identity = digest(0xee);
    });
    aggregate_adapter_refuses([](auto& value) {
        value.worker = worker();
    });
}

void owner_comparison_adapter_preserves_nonregression_outcome() {
    const auto public_permit = comparison_permit();
    auto permit = OwnerComparisonPermitAuthority::test_only_mint(
        public_permit);
    auto evidence = ChildCompletionEvidenceAuthority::test_only_mint(
        valid_comparison(public_permit));
    auto completed = RuntimeCompletionBridge::owner_comparison(
        std::move(permit), std::move(evidence));
    const auto& receipt = completed.completion.public_receipt();
    assert(receipt.comparison_selection ==
           public_permit.selection.comparison_selection);
    assert(receipt.permit_identity == public_permit.permit_identity);
    assert(receipt.baseline_aggregate == public_permit.baseline_aggregate);
    assert(receipt.candidate_aggregate == public_permit.candidate_aggregate);
    assert(receipt.comparison_receipt == digest(13));
    assert(receipt.outcome == OwnerComparisonOutcome::NonRegressionPass);
    assert(receipt.worker == public_permit.selection.comparison_worker);
}

template<class Change>
void owner_comparison_adapter_refuses(Change&& change) {
    const auto public_permit = comparison_permit();
    auto permit = OwnerComparisonPermitAuthority::test_only_mint(
        public_permit);
    auto evidence_value = valid_comparison(public_permit);
    change(evidence_value);
    evidence_value.process_identity = recompute_process_identity(
        evidence_value);
    bool refused = false;
    try {
        auto evidence = ChildCompletionEvidenceAuthority::test_only_mint(
            evidence_value);
        (void)RuntimeCompletionBridge::owner_comparison(
            std::move(permit), std::move(evidence));
    } catch (const Refused&) {
        refused = true;
    }
    assert(refused);
}

void owner_comparison_adapter_rejects_wrong_outcome_permit_or_worker() {
    owner_comparison_adapter_refuses([](auto& value) {
        value.comparison_outcome =
            static_cast<OwnerComparisonOutcome>(99);
    });
    owner_comparison_adapter_refuses([](auto& value) {
        value.permit_identity = digest(0xee);
    });
    owner_comparison_adapter_refuses([](auto& value) {
        value.worker = worker();
    });
}

void runtime_bridge_drives_one_run_without_truth_export() {
    const auto selected = binding();
    PublicTrialCaptureCompletion capture_receipt{};
    capture_receipt.binding = selected;
    capture_receipt.completion_identity = digest(0xe0);
    RunMeasurement run(
        TrialCaptureCompletionAuthority::test_only_mint(capture_receipt));

    auto observer_permit = run.issue_observer();
    const auto observer_value = valid_observer(
        observer_permit.public_receipt());
    auto observer_output = sealed_output(
        observer_permit.public_receipt().binding,
        RuntimeChildRole::Observer, NO_OWNER,
        observer_permit.public_receipt().permit_identity, observer_value);
    auto observer_evidence =
        ChildCompletionEvidenceAuthority::test_only_mint(observer_value);
    auto observer_execution =
        std::move(observer_permit).test_only_take_execution();
    auto observer = RuntimeCompletionBridge::observation(
        std::move(observer_execution), std::move(observer_evidence),
        std::move(observer_output), empirical_fixture::exact(selected));
    const auto observation_receipt =
        observer.completion.public_receipt().observation_receipt;
    run.accept_observer(std::move(observer.permit),
                        std::move(observer.completion));

    const PublicBarrierFreeze barrier{
        .binding = selected,
        .trial_capture_identity = capture_receipt.completion_identity,
        .observation_receipt = observation_receipt,
        .barrier_receipt = digest(0xe1),
        .outer_parent_process = selected.outer_parent_process,
        .outer_parent_executable = selected.outer_parent_executable,
        .manifest_recomputation_receipt =
            selected.finite_manifest.parent_recomputation_identity,
    };
    run.freeze_barrier(BarrierFreezeAuthority::test_only_mint(barrier));
    auto candidate_truth_release =
        run.issue_candidate_truth_barrier_release();
    (void)candidate_truth_release;

    std::array<Digest, 3> score_receipts{};
    for (unsigned owner = 0; owner < 3; ++owner) {
        auto score_permit = run.issue_score(owner);
        const auto score_value = valid_score(score_permit.public_receipt());
        auto score_output = sealed_output(
            score_permit.public_receipt().binding,
            RuntimeChildRole::OwnerScore,
            score_permit.public_receipt().owner,
            score_permit.public_receipt().permit_identity, score_value);
        auto score_evidence =
            ChildCompletionEvidenceAuthority::test_only_mint(score_value);
        auto score = RuntimeCompletionBridge::owner_score(
            execution_permit(std::move(score_permit)),
            std::move(score_evidence), std::move(score_output));
        score_receipts[owner] =
            score.completion.public_receipt().score_receipt;
        run.accept_score(std::move(score.permit),
                         std::move(score.completion));
    }

    auto aggregate_permit = run.issue_aggregate();
    auto aggregate_evidence =
        ChildCompletionEvidenceAuthority::test_only_mint(
            valid_aggregate(aggregate_permit.public_receipt()));
    auto aggregate = RuntimeCompletionBridge::aggregate(
        std::move(aggregate_permit), std::move(aggregate_evidence));
    auto completed = run.accept_aggregate(
        std::move(aggregate.permit), std::move(aggregate.completion));
    const auto& receipt = completed.public_receipt();
    assert(receipt.outcome == AggregateOutcome::CandidatePass);
    assert(receipt.observation_receipt == observation_receipt);
    assert(receipt.score_receipts == score_receipts);
    assert(receipt.aggregate_receipt == digest(13));
    assert(receipt.completion_identity != Digest{});
}

void sealed_owner_outputs_remain_distinct_despite_reused_opaque_evidence() {
    const auto selected = binding();
    PublicTrialCaptureCompletion capture_receipt{};
    capture_receipt.binding = selected;
    capture_receipt.completion_identity = digest(0xe0);
    RunMeasurement run(
        TrialCaptureCompletionAuthority::test_only_mint(capture_receipt));

    auto observer_permit = run.issue_observer();
    const auto observer_value = valid_observer(
        observer_permit.public_receipt());
    auto observer_output = sealed_output(
        observer_permit.public_receipt().binding,
        RuntimeChildRole::Observer, NO_OWNER,
        observer_permit.public_receipt().permit_identity, observer_value);
    auto observer_evidence =
        ChildCompletionEvidenceAuthority::test_only_mint(observer_value);
    auto observer_execution =
        std::move(observer_permit).test_only_take_execution();
    auto observer = RuntimeCompletionBridge::observation(
        std::move(observer_execution), std::move(observer_evidence),
        std::move(observer_output), empirical_fixture::exact(selected));
    const auto observation_receipt =
        observer.completion.public_receipt().observation_receipt;
    run.accept_observer(std::move(observer.permit),
                        std::move(observer.completion));

    const PublicBarrierFreeze barrier{
        .binding = selected,
        .trial_capture_identity = capture_receipt.completion_identity,
        .observation_receipt = observation_receipt,
        .barrier_receipt = digest(0xe1),
        .outer_parent_process = selected.outer_parent_process,
        .outer_parent_executable = selected.outer_parent_executable,
        .manifest_recomputation_receipt =
            selected.finite_manifest.parent_recomputation_identity,
    };
    run.freeze_barrier(BarrierFreezeAuthority::test_only_mint(barrier));
    auto candidate_truth_release =
        run.issue_candidate_truth_barrier_release();
    (void)candidate_truth_release;

    for (unsigned owner = 0; owner < 3; ++owner) {
        auto score_permit = run.issue_score(owner);
        auto value = valid_score(score_permit.public_receipt());
        value.opaque_completion_authority_identity = digest(0xf5);
        value.opaque_capsule_authority_identity = digest(0xf6);
        value.process_identity = recompute_process_identity(value);
        auto score_output = sealed_output(
            score_permit.public_receipt().binding,
            RuntimeChildRole::OwnerScore,
            score_permit.public_receipt().owner,
            score_permit.public_receipt().permit_identity, value);
        auto score_evidence =
            ChildCompletionEvidenceAuthority::test_only_mint(value);
        auto score = RuntimeCompletionBridge::owner_score(
            execution_permit(std::move(score_permit)),
            std::move(score_evidence), std::move(score_output));
        run.accept_score(std::move(score.permit),
                         std::move(score.completion));
    }

    const auto aggregate = run.issue_aggregate().public_receipt();
    assert(aggregate.score_receipts[0] != aggregate.score_receipts[1] &&
           aggregate.score_receipts[0] != aggregate.score_receipts[2] &&
           aggregate.score_receipts[1] != aggregate.score_receipts[2] &&
           aggregate.capsule_seals[0] != aggregate.capsule_seals[1] &&
           aggregate.capsule_seals[0] != aggregate.capsule_seals[2] &&
           aggregate.capsule_seals[1] != aggregate.capsule_seals[2]);
}

RunBinding baseline_binding() {
    auto value = binding();
    value.classification = Classification::TransparentBaseline;
    value.run_selection = digest(0xe2);
    value.trial = digest(0xe3);
    value.attempt = digest(0xe4);
    value.cohort = digest(0xe5);
    value.capture = digest(0xe6);
    value.financial_runs = {digest(0xe7), digest(0xe8)};
    value.round_attempts = {digest(0xe9), digest(0xea)};
    value.round_cohorts = {digest(0xeb), digest(0xec)};
    value.projections = {digest(0xed), digest(0xee)};
    return value;
}

PublicRunAggregateCompletion run_aggregate(
        const RunBinding& selected, AggregateOutcome outcome,
        unsigned char seed) {
    return {
        .binding = selected,
        .trial_capture_identity = digest(seed),
        .observation_receipt = digest(seed + 1),
        .observation_process = digest(seed + 2),
        .barrier = digest(seed + 3),
        .score_receipts = {digest(seed + 4), digest(seed + 5),
                           digest(seed + 6)},
        .capsule_seals = {digest(seed + 7), digest(seed + 8),
                          digest(seed + 9)},
        .score_processes = {digest(seed + 10), digest(seed + 11),
                            digest(seed + 12)},
        .aggregate_child_exit = digest(seed + 13),
        .aggregate_process = digest(seed + 14),
        .aggregate_receipt = digest(seed + 15),
        .outer_parent_process = selected.outer_parent_process,
        .outer_parent_executable = selected.outer_parent_executable,
        .manifest_recomputation_receipt =
            selected.finite_manifest.parent_recomputation_identity,
        .outcome = outcome,
        .completion_identity = digest(seed + 16),
    };
}

void runtime_bridge_mints_only_bounded_actual_acceptance() {
    const auto baseline_run = baseline_binding();
    const auto candidate_run = binding();
    const PublicComparisonSelection selection{
        .comparison_selection = candidate_run.comparison_selection,
        .selection_identity = digest(0xf0),
        .method = candidate_run.method,
        .workload = candidate_run.workload,
        .source_closure = candidate_run.source_closure,
        .runtime = candidate_run.runtime,
        .finite_manifest = candidate_run.finite_manifest,
        .comparison_worker = worker(
            candidate_run.finite_manifest.entries.at(9)),
        .outer_parent_process = candidate_run.outer_parent_process,
        .outer_parent_executable = candidate_run.outer_parent_executable,
        .manifest_recomputation_receipt =
            candidate_run.finite_manifest.parent_recomputation_identity,
        .baseline_run = baseline_run.run_selection,
        .candidate_run = candidate_run.run_selection,
    };
    ComparisonMeasurement comparison(
        ComparisonSelectionAuthority::test_only_mint(selection),
        RunAggregateCompletionAuthority::test_only_mint(run_aggregate(
            baseline_run, AggregateOutcome::BaselineControlDetected, 0x80)),
        RunAggregateCompletionAuthority::test_only_mint(run_aggregate(
            candidate_run, AggregateOutcome::CandidatePass, 0xa0)));
    auto permit = comparison.issue_owner_comparison();
    auto evidence = ChildCompletionEvidenceAuthority::test_only_mint(
        valid_comparison(permit.public_receipt()));
    auto child = RuntimeCompletionBridge::owner_comparison(
        std::move(permit), std::move(evidence));
    auto accepted = comparison.accept_owner_comparison(
        std::move(child.permit), std::move(child.completion));
    const auto& receipt = accepted.public_receipt();
    assert(receipt.scope == PrivacyScope::BatchPaymentPreNetworkOnly);
    assert(receipt.comparison_selection == selection.comparison_selection);
    assert(receipt.owner_comparison_receipt == digest(13));
    assert(receipt.pass_identity != Digest{});
}

} // namespace

int main() {
    valid_evidence_is_move_only_and_one_shot();
    malformed_or_unbound_evidence_refuses();
    observer_adapter_preserves_the_genuine_permit();
    observer_adapter_rejects_cross_run_or_worker_substitution();
    observer_wrong_permit_burns_output_and_empirical_before_refusal();
    owner_score_adapter_preserves_owner_scope();
    owner_score_adapter_rejects_wrong_owner_permit_or_worker();
    aggregate_adapter_preserves_candidate_outcome();
    aggregate_adapter_rejects_wrong_outcome_permit_or_worker();
    owner_comparison_adapter_preserves_nonregression_outcome();
    owner_comparison_adapter_rejects_wrong_outcome_permit_or_worker();
    runtime_bridge_drives_one_run_without_truth_export();
    sealed_owner_outputs_remain_distinct_despite_reused_opaque_evidence();
    runtime_bridge_mints_only_bounded_actual_acceptance();
    source_status_is_truthful();
}
