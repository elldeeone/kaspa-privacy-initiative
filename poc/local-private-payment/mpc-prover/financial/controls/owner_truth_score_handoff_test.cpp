#include "../owner_truth_score_handoff.hpp"
#include "../authenticated_baseline_owner_receiver.hpp"
#include "../fresh_owner_process_adapter.hpp"
#include "../../../private_batch_trial/privacy_measurement_worker_capsule.hpp"

#include <array>
#include <cassert>
#include <cerrno>
#include <concepts>
#include <string_view>
#include <sys/socket.h>
#include <unistd.h>

using namespace kpb::measurement;
using namespace kpb::measurement::runtime_bridge;
using namespace kpi::mpc::financial;
using namespace kpi::mpc::financial::registered_driver;
using namespace kpi::mpc::financial::registered_driver::baseline_disclosure;
using namespace kpi::mpc::financial::registered_driver::owner_truth_handoff;

namespace {
Digest id(unsigned long long value) {
    Digest result{};
    for (unsigned index = 0; index < 8; ++index)
        result[index] = static_cast<unsigned char>(value >> (8 * index));
    result[31] = static_cast<unsigned char>(value ^ 0xa7U);
    return result;
}

template<class Callable> void refused(Callable&& callable) {
    bool rejected = false;
    try { callable(); }
    catch (const kpb::measurement::Refused&) { rejected = true; }
    catch (const identity_registry::Refused&) { rejected = true; }
    assert(rejected);
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
            .source_identity = id(seed),
            .build_identity = id(seed + 0x10),
            .runtime_identity = id(seed + 0x20),
            .assets_identity = id(seed + 0x30),
            .pinned_executable_identity = id(seed + 0x40),
            .launcher_identity = id(seed + 0x50),
        };
    }
    return FiniteManifestBinding{
        .manifest_identity = recompute_finite_manifest_identity(entries),
        .parent_recomputation_identity = id(0xcf),
        .entries = entries,
    };
}

RunBinding binding(Classification classification) {
    const auto manifest = finite_manifest();
    const auto& capture = manifest.entries.at(1);
    RunBinding result{
        .classification = classification,
        .comparison_selection = id(0x801),
        .run_selection = id(0x802),
        .trial = id(0x20),
        .attempt = id(0x803),
        .cohort = id(0x804),
        .capture = id(0x805),
        .method = id(0x806),
        .workload = id(0x807),
        .source_closure = id(0x808),
        .runtime = id(0x809),
        .finite_manifest = manifest,
        .outer_parent_process = id(0x80a),
        .outer_parent_executable = id(0x80b),
        .capture_source = capture.source_identity,
        .capture_build = capture.build_identity,
        .capture_runtime = capture.runtime_identity,
        .capture_launcher = capture.launcher_identity,
        .observer_worker = worker(manifest.entries.at(6)),
        .score_worker = worker(manifest.entries.at(7)),
        .aggregate_worker = worker(manifest.entries.at(8)),
        .financial_runs = {id(0x11), id(0x12)},
        .round_attempts = {id(0x31), id(0x32)},
        .round_cohorts = {id(0x41), id(0x42)},
        .round_capture_plans = {id(0x51), id(0x52)},
        .projections = {id(0x61), id(0x62)},
    };
    return result;
}

OwnerScorePermitSplit split(Classification classification, unsigned owner,
                            Digest barrier = id(0x901)) {
    return std::move(OwnerScorePermitAuthority::test_only_mint(
        PublicOwnerScorePermit{
            .binding = binding(classification),
            .owner = owner,
            .trial_capture_identity = id(0x902),
            .observation_receipt = id(0x903),
            .barrier = barrier,
            .permit_identity = id(0x904),
        })).split_for_truth_release();
}

PrivatePartyBaselineOwnerEffects baseline_value(
        unsigned round, unsigned role) {
    PrivatePartyBaselineOwnerEffects result{
        .classification =
            CaptureClassification::ExplicitOwnerPublicEffectsBaseline,
        .round = round,
        .role = role,
        .run = id(0x10 + round),
        .trial = id(0x20),
        .attempt = id(0x30 + round),
        .cohort = id(0x40 + round),
        .capture_plan_identity = id(0x50 + round),
        .projection_identity = id(0x60 + round),
        .context_identity = id(0x70 + round),
        .relation_source_identity = id(0x80),
        .owner_effects_recipe_identity = id(0x81),
        .baseline_plan_identity = id(0x90 + 3 * round + role),
        .verified_egress_identity = id(0xa0 + 3 * round + role),
        .policy_identity = id(0xb0),
        .roster_authority_identity = id(0xb1),
        .roster_root_identity = id(0xb2),
        .consent_nonce = id(0xc0 + round),
    };
    for (unsigned owner = 0; owner < 3; ++owner) {
        result.owner_contracts[owner] = id(0x100 + 8 * round + owner);
        result.logical_owner_identities[owner] = id(0x180 + owner);
        result.pre_disclosure_challenge_identities[owner] =
            id(0x1c0 + 8 * round + owner);
        result.owner_sessions[owner] =
            id(0x200 + 32 * round + 4 * role + owner);
        auto& truth = result.owner_truth[owner];
        truth.owner = owner;
        truth.round = round;
        truth.run = result.run;
        truth.trial = result.trial;
        truth.attempt = result.attempt;
        truth.cohort = result.cohort;
        truth.capture_plan_identity = result.capture_plan_identity;
        truth.projection_identity = result.projection_identity;
        truth.context_identity = result.context_identity;
        truth.owner_contract_identity = result.owner_contracts[owner];
        truth.logical_owner_identity = result.logical_owner_identities[owner];
        truth.roster_authority_identity = result.roster_authority_identity;
        truth.roster_root_identity = result.roster_root_identity;
        truth.pre_disclosure_challenge_identity =
            result.pre_disclosure_challenge_identities[owner];
        truth.public_nullifier = id(0x300 + 8 * round + owner);
        truth.public_tuple_hashes = {
            id(0x400 + 16 * round + 2 * owner),
            id(0x401 + 16 * round + 2 * owner)};
        truth.public_tuple_commitments = {
            id(0x500 + 16 * round + 2 * owner),
            id(0x501 + 16 * round + 2 * owner)};
    }
    return result;
}

BaselineOwnerScoringLaunchAuthority baseline_launch() {
    BaselineOwnerScoringParentCollector parent;
    for (unsigned round = 1; round <= 2; ++round)
        for (unsigned role = 0; role < 3; ++role)
            parent.submit(PartyBaselineOwnerEffectsAuthority::test_only_mint(
                baseline_value(round, role)));
    return parent.finish();
}

struct CandidateEndpoint {
    fresh_owner_issuance::CandidateOwnerTruthEndpointAuthority authority;
    int peer{-1};
    explicit CandidateEndpoint(
            fresh_owner_issuance::PublicCandidateOwnerTruthEndpoint receipt)
        : authority([&] {
              int sockets[2]{-1, -1};
              assert(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC,
                                  0, sockets) == 0);
              peer = sockets[1];
              return fresh_owner_issuance::
                  CandidateOwnerTruthEndpointAuthority::test_only_mint(
                      receipt, sockets[0]);
          }()) {}
    CandidateEndpoint(const CandidateEndpoint&) = delete;
    ~CandidateEndpoint() {
        if (peer >= 0)
            while (::close(peer) != 0 && errno == EINTR) {}
    }
};

fresh_owner_issuance::PublicCandidateOwnerTruthEndpoint candidate_receipt(
        unsigned owner = 1, Digest barrier = id(0x901)) {
    const auto selected = binding(Classification::HiddenCandidate);
    return {
        .classification = CaptureClassification::HiddenCandidate,
        .owner_component = owner,
        .fixed_fd = fresh_owner_issuance::FRESH_OWNER_FIXED_TRUTH_FD,
        .endpoint_identity = id(0xa01 + owner),
        .feeder_session_identity = id(0xa11 + owner),
        .trial = selected.trial,
        .barrier_identity = barrier,
        .financial_runs = selected.financial_runs,
        .attempts = selected.round_attempts,
        .cohorts = selected.round_cohorts,
        .capture_plan_identities = selected.round_capture_plans,
        .projection_identities = selected.projections,
        .context_identities = {id(0xa20), id(0xa21)},
        .feeder_pid = static_cast<std::int64_t>(::getpid()),
        .feeder_exit_identity = id(0xa30 + owner),
    };
}

void require_handoff(OwnerTruthScoreHandoff& handoff,
                     Classification classification, unsigned owner) {
    auto execution = handoff.take_execution_permit();
    auto endpoint = handoff.take_truth_endpoint();
    const auto& permit = execution.public_receipt();
    const auto& truth = endpoint.public_receipt();
    assert(permit.owner == owner &&
           truth.owner == owner &&
           truth.kind == MeasurementInputKind::OwnerTruth &&
           truth.fixed_fd == MEASUREMENT_SCORE_OWNER_TRUTH_FD &&
           truth.lineage.classification == classification &&
           truth.lineage.trial == permit.binding.trial &&
           truth.lineage.barrier == permit.barrier &&
           truth.lineage.capture_plan_identities ==
               permit.binding.round_capture_plans &&
           truth.lineage.financial_runs == permit.binding.financial_runs &&
           truth.lineage.round_attempts == permit.binding.round_attempts &&
           truth.lineage.round_cohorts == permit.binding.round_cohorts &&
           truth.lineage.projections == permit.binding.projections);
    refused([&] { (void)handoff.take_execution_permit(); });
    refused([&] { (void)handoff.take_truth_endpoint(); });
}

void baseline_happy() {
    auto launch = baseline_launch();
    auto handoff = OwnerTruthScoreHandoffBridge::prepare(
        split(Classification::TransparentBaseline, 1),
        launch.take_owner(1));
    require_handoff(handoff, Classification::TransparentBaseline, 1);
}

void candidate_happy() {
    CandidateEndpoint endpoint(candidate_receipt());
    auto handoff = OwnerTruthScoreHandoffBridge::prepare(
        split(Classification::HiddenCandidate, 1),
        std::move(endpoint.authority));
    require_handoff(handoff, Classification::HiddenCandidate, 1);
}

void substitution() {
    {
        CandidateEndpoint endpoint(candidate_receipt(1, id(0x911)));
        refused([&] {
            (void)OwnerTruthScoreHandoffBridge::prepare(
                split(Classification::HiddenCandidate, 1, id(0x901)),
                std::move(endpoint.authority));
        });
    }
    {
        auto receipt = candidate_receipt();
        std::swap(receipt.capture_plan_identities[0],
                  receipt.capture_plan_identities[1]);
        CandidateEndpoint endpoint(receipt);
        refused([&] {
            (void)OwnerTruthScoreHandoffBridge::prepare(
                split(Classification::HiddenCandidate, 1),
                std::move(endpoint.authority));
        });
    }
    {
        CandidateEndpoint endpoint(candidate_receipt(2));
        refused([&] {
            (void)OwnerTruthScoreHandoffBridge::prepare(
                split(Classification::HiddenCandidate, 1),
                std::move(endpoint.authority));
        });
    }
    {
        CandidateEndpoint endpoint(candidate_receipt());
        refused([&] {
            (void)OwnerTruthScoreHandoffBridge::prepare(
                split(Classification::TransparentBaseline, 1),
                std::move(endpoint.authority));
        });
    }
    {
        auto launch = baseline_launch();
        refused([&] {
            (void)OwnerTruthScoreHandoffBridge::prepare(
                split(Classification::HiddenCandidate, 0),
                launch.take_owner(0));
        });
    }
}

void replay() {
    CandidateEndpoint endpoint(candidate_receipt());
    auto first = OwnerTruthScoreHandoffBridge::prepare(
        split(Classification::HiddenCandidate, 1),
        std::move(endpoint.authority));
    (void)first;
    refused([&] {
        (void)OwnerTruthScoreHandoffBridge::prepare(
            split(Classification::HiddenCandidate, 1),
            std::move(endpoint.authority));
    });
}

template<class T> concept HasFd = requires(T& value) { value.fd(); };
template<class T> concept HasBytes = requires(T& value) { value.bytes(); };
template<class T> concept HasBodyHash = requires(T& value) {
    value.body_sha256();
};

void surface() {
    using Candidate =
        fresh_owner_issuance::CandidateOwnerTruthEndpointAuthority;
    static_assert(!std::default_initializable<OwnerTruthScoreHandoff>);
    static_assert(!std::copy_constructible<OwnerTruthScoreHandoff>);
    static_assert(!HasFd<OwnerTruthScoreHandoff> &&
                  !HasBytes<OwnerTruthScoreHandoff> &&
                  !HasBodyHash<OwnerTruthScoreHandoff>);
    static_assert(!HasFd<Candidate> && !HasBytes<Candidate> &&
                  !HasBodyHash<Candidate>);
    static_assert(
        baseline_disclosure::truth_capsule_schema::PACKET_BYTES == 813);
    static_assert(
        fresh_owner_issuance::candidate_truth_schema::PACKET_BYTES == 813);
    static_assert(baseline_disclosure::truth_capsule_schema::MAGIC ==
                  fresh_owner_issuance::candidate_truth_schema::MAGIC);
    static_assert(
        baseline_disclosure::truth_capsule_schema::
            HIDDEN_CANDIDATE_CLASSIFICATION == 1 &&
        baseline_disclosure::truth_capsule_schema::
            EXPLICIT_BASELINE_CLASSIFICATION == 2);
}
} // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    const std::string_view mode(argv[1]);
    if (mode == "baseline") baseline_happy();
    else if (mode == "candidate") candidate_happy();
    else if (mode == "substitution") substitution();
    else if (mode == "replay") replay();
    else if (mode == "surface") surface();
    else return 2;
}
