#include "../fresh_owner_trial_issuance.hpp"
#include "../registered_parent_role_fork.hpp"
#include "../../../private_batch_trial/privacy_fresh_owner_transactional_replay_authority.hpp"
#include "../../../private_batch_trial/privacy_registered_fresh_trial_capture_topology_reservation.hpp"

#include <array>
#include <atomic>
#include <cassert>
#include <concepts>
#include <cstdlib>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using namespace kpi::mpc;
using namespace kpi::mpc::financial;
using namespace kpi::mpc::financial::fresh_owner_issuance;
using namespace kpi::mpc::financial::registered_driver;
namespace replay = kpb::measurement::fresh_owner_transactional_replay;
using kpi::mpc::financial::registered_driver::CaptureClassification;

namespace {
std::atomic_bool fail_allocations{};
}

void* operator new(std::size_t size) {
    if (fail_allocations.load()) throw std::bad_alloc();
    if (void* value = std::malloc(size == 0 ? 1 : size)) return value;
    throw std::bad_alloc();
}

namespace {

Digest id(unsigned value) {
    Digest result{};
    result[0] = static_cast<unsigned char>(value);
    result[1] = static_cast<unsigned char>(value >> 8);
    result[31] = static_cast<unsigned char>(value ^ 0xa7U);
    return result;
}

std::string hex(unsigned value) {
    return identity_registry::hex(id(value));
}

LogicalOwnerIdentity logical_id(unsigned owner) {
    LogicalOwnerIdentity result{};
    result[0] = static_cast<unsigned char>(0x30 + owner);
    result[31] = static_cast<unsigned char>(0xd0 + owner);
    return result;
}

class TestVerifier final : public LongLivedOwnerProofVerifier {
    LogicalOwnerIdentity identity_;
public:
    explicit TestVerifier(LogicalOwnerIdentity identity)
        : identity_(identity) {}
private:
    LogicalOwnerIdentity logical_identity() const override {
        return identity_;
    }
    bool verify(std::span<const unsigned char> challenge,
                std::span<const unsigned char> proof) const override {
        return challenge.size() == 2 && proof.size() == 2 &&
               proof[0] == identity_[0] && proof[1] == challenge[0];
    }
};

OwnerInputContract contract(unsigned owner, unsigned round) {
    const unsigned base = round == 1 ? 0x100 : 0x200;
    return OwnerInputContract{
        .run_nonce = hex(base + 1),
        .model_identity = hex(0x300),
        .source_identity = hex(0x301),
        .proving_key_identity = hex(0x302),
        .verifying_key_identity = hex(0x303),
        .cohort_identity = hex(base + 2),
        .owner_id = static_cast<int>(owner),
        .input_count = 2'635'409,
        .server_certificate_sha256 = {
            hex(base + 10), hex(base + 11), hex(base + 12)},
        .owner_certificate_sha256 = hex(base + 20 + owner),
        .trace_identity = hex(0x304),
        .layout_identity = hex(0x305),
    };
}

PublicOwnerIssuanceReceipt receipt(unsigned owner) {
    PublicOwnerIssuanceReceipt value{
        .classification =
            CaptureClassification::ExplicitOwnerPublicEffectsBaseline,
        .authority_identity = id(1),
        .registration_identity = id(2),
        .service_identity = id(3),
        .controller_source_identity = id(4),
        .controller_build_identity = id(5),
        .owner_issuer_source_identity = id(6),
        .owner_issuer_build_identity = id(7),
        .run = id(8),
        .trial = id(9),
        .root_identity = id(10),
        .baseline_policy_identity = id(0x700),
        .owner_component = owner,
        .owner_process_identity = id(20 + owner),
    };
    for (unsigned round = 1; round <= 2; ++round) {
        const unsigned base = round == 1 ? 0x100 : 0x200;
        auto& item = value.rounds[round - 1];
        item.round = round;
        item.attempt = id(base + 1);
        item.cohort = id(base + 2);
        item.accepted_input_head_identity = id(base + 3);
        item.history_gate_identity = id(base + 4);
        item.contract = contract(owner, round);
        item.file_identity = id(base + 30 + owner);
        item.file_metadata_identity = id(base + 40 + owner);
        item.file_bytes = OWNER_PRIVATE_INPUT_V2_BYTES;
        item.owner_tls_spki_identity = id(base + 50 + owner);
        item.server_tls_spki_identities = {
            id(base + 60), id(base + 61), id(base + 62)};
    }
    return value;
}

OwnerLocalIssuanceAuthority owner_authority(unsigned owner) {
    return OwnerLocalIssuanceAuthority::test_only_mint(
        receipt(owner),
        std::make_shared<TestVerifier>(logical_id(owner)), id(0x400 + owner));
}

OwnerLocalIssuanceAuthority mint(
        PublicOwnerIssuanceReceipt value,
        LogicalOwnerIdentity identity, Digest nonce) {
    return OwnerLocalIssuanceAuthority::test_only_mint(
        std::move(value), std::make_shared<TestVerifier>(identity), nonce);
}

class MemoryReplayRegistry final : public ExternalOwnerIssuanceReplayRegistry {
    std::vector<Digest> consumed_;
public:
    void consume(std::span<const Digest> values) override {
        for (const auto& value : values)
            for (const auto& prior : consumed_)
                if (value == prior) throw identity_registry::Refused();
        consumed_.insert(consumed_.end(), values.begin(), values.end());
    }
};

OwnerIssuanceReplayGuardAuthority replay_guard(
        const std::shared_ptr<ExternalOwnerIssuanceReplayRegistry>& registry) {
    return OwnerIssuanceReplayGuardAuthority::test_only_mint(
        PublicOwnerIssuanceReplayPolicy{
            .authority_identity = id(0x500),
            .policy_identity = id(0x501),
            .permission_separated = true,
            .monotonic = true,
            .child_path_exposed = false,
            .child_fd_exposed = false,
        }, registry);
}

std::array<OwnerLocalIssuanceAuthority, 3> owners() {
    return {owner_authority(0), owner_authority(1), owner_authority(2)};
}

class UnreachableRoundProgram final : public RegisteredRoleChildProgram {
public:
    int run(ParentAuthenticatedPartyDeliveryAuthority&&,
            ChildRoleCompletionEndpointAuthority&&) override {
        return 99;
    }
};

class PreidentityRoleProgram final :
        public RegisteredPreIdentityPersistentRoleChildProgram {
    std::array<UnreachableRoundProgram, 2> rounds_;
public:
    RegisteredRoleChildProgram& round_program(unsigned round) override {
        assert(round == 1 || round == 2);
        return rounds_[round - 1];
    }
};

class PreparedReplay final : public replay::OwnerReplayPreparedOperation {
    replay::OwnerReplayBackendCommitDisposition disposition_;
public:
    explicit PreparedReplay(
            replay::OwnerReplayBackendCommitDisposition disposition)
        : disposition_(disposition) {}
    replay::OwnerReplayBackendCommitDisposition
    commit_prepared() noexcept override { return disposition_; }
};

class TransactionalReplayRegistry final :
        public replay::TransactionalOwnerReplayRegistry {
    replay::OwnerReplayBackendCommitDisposition disposition_;
    bool fail_after_prepare_{};
public:
    explicit TransactionalReplayRegistry(
            replay::OwnerReplayBackendCommitDisposition disposition,
            bool fail_after_prepare = false)
        : disposition_(disposition),
          fail_after_prepare_(fail_after_prepare) {}
    std::unique_ptr<replay::OwnerReplayPreparedOperation> prepare(
            const replay::ExactOwnerReplaySet&) override {
        auto result = std::make_unique<PreparedReplay>(disposition_);
        if (fail_after_prepare_) fail_allocations = true;
        return result;
    }
};

FreshOwnerTransactionalIssuanceOutcomeAuthority transactional_outcome(
        PreidentityRoleProgram& program,
        replay::OwnerReplayBackendCommitDisposition disposition,
        bool fail_after_prepare = false) {
    auto process = RegisteredParentPersistentRoleFork::reserve(program);
    auto topology_permit = process.issue_topology_reservation_permit();
    auto topology = FreshTrialCaptureTopologyReservationBridge::reserve(
        std::move(topology_permit));
    auto ready = RegisteredPreidentityReadyBridge::join(
        std::move(topology), std::move(process));
    auto issuance = RegisteredPreidentityReadyIssuanceBridge::begin(
        std::move(ready));
    auto owner0 = OwnerLocalIssuanceAuthority::test_only_mint(
        receipt(0), std::make_shared<TestVerifier>(logical_id(0)), id(0x400),
        RegisteredPreidentityReadyIssuanceBridge::take_owner_permit(
            issuance, 0));
    auto owner1 = OwnerLocalIssuanceAuthority::test_only_mint(
        receipt(1), std::make_shared<TestVerifier>(logical_id(1)), id(0x401),
        RegisteredPreidentityReadyIssuanceBridge::take_owner_permit(
            issuance, 1));
    auto owner2 = OwnerLocalIssuanceAuthority::test_only_mint(
        receipt(2), std::make_shared<TestVerifier>(logical_id(2)), id(0x402),
        RegisteredPreidentityReadyIssuanceBridge::take_owner_permit(
            issuance, 2));
    auto residual = RegisteredPreidentityReadyIssuanceBridge::finish(
        std::move(issuance));
    auto registry = replay::FreshOwnerTransactionalReplayTestBridge::
        mint_registry(
            std::make_shared<TransactionalReplayRegistry>(
                disposition, fail_after_prepare),
            id(0x800), id(0x801));
    try {
        auto result = FreshOwnerTransactionalIssuanceBridge::join_exact_three(
            std::move(residual), std::move(owner0), std::move(owner1),
            std::move(owner2), std::move(registry), id(0x600));
        fail_allocations = false;
        return result;
    } catch (...) {
        fail_allocations = false;
        throw;
    }
}

OwnerLocalIssuanceAuthority hidden_owner_authority(unsigned owner) {
    auto value = receipt(owner);
    value.classification = CaptureClassification::HiddenCandidate;
    value.baseline_policy_identity = {};
    return OwnerLocalIssuanceAuthority::test_only_mint(
        std::move(value),
        std::make_shared<TestVerifier>(logical_id(owner)), id(0x400 + owner));
}

std::array<OwnerLocalIssuanceAuthority, 3> hidden_owners() {
    return {hidden_owner_authority(0), hidden_owner_authority(1),
            hidden_owner_authority(2)};
}

template<class Callable>
void refuses(Callable&& callable) {
    bool did_refuse = false;
    try { callable(); }
    catch (const identity_registry::Refused&) { did_refuse = true; }
    assert(did_refuse);
}

void happy_join_and_split() {
    static_assert(!std::copy_constructible<OwnerLocalIssuanceAuthority>);
    static_assert(!std::copy_constructible<FreshOwnerTrialIssuanceAuthority>);
    static_assert(!std::copy_constructible<FreshOwnerRoundAuthority>);
    static_assert(!std::copy_constructible<BaselineOwnerRosterAuthority>);
    static_assert(!std::default_initializable<OwnerLocalIssuanceAuthority>);

    auto registry = std::make_shared<MemoryReplayRegistry>();
    auto selected = FreshOwnerTrialIssuanceBridge::join_exact_three(
        owners(), replay_guard(registry), id(0x600));
    const auto& public_receipt = selected.public_receipt();
    assert(public_receipt.run == id(8));
    assert(public_receipt.trial == id(9));
    assert(public_receipt.root_identity == id(10));
    for (unsigned owner = 0; owner < 3; ++owner) {
        assert(public_receipt.owners[owner].owner_component == owner);
        assert(public_receipt.owners[owner].logical_owner_binding != Digest{});
        assert(public_receipt.owners[owner].logical_owner_binding !=
               logical_id(owner));
    }

    auto split = FreshOwnerTrialIssuanceBridge::split(std::move(selected));
    auto round1 = split.take_round(1);
    auto round2 = split.take_round(2);
    assert(round1.public_receipt().round == 1);
    assert(round2.public_receipt().round == 2);
    for (unsigned owner = 0; owner < 3; ++owner) {
        assert(round1.test_only_contracts()[owner].owner_id ==
               static_cast<int>(owner));
        assert(round2.test_only_contracts()[owner].owner_id ==
               static_cast<int>(owner));
        assert(round1.test_only_contracts()[owner].owner_certificate_sha256 !=
               round2.test_only_contracts()[owner].owner_certificate_sha256);
    }
    auto roster = split.take_baseline_roster();
    auto receiver_split = BaselineOwnerRosterBridge::split(
        std::move(roster));
    auto receiver = receiver_split.take(1, 0);
    auto session = BaselineOwnerRosterReceiverBridge::consume(
        std::move(receiver),
        CaptureClassification::ExplicitOwnerPublicEffectsBaseline,
        1, 0, id(8), id(9), id(0x700));
    for (unsigned owner = 0; owner < 3; ++owner) {
        const std::array<unsigned char, 2> challenge{
            static_cast<unsigned char>(0x80 + owner), 0x55};
        const std::array<unsigned char, 2> proof{
            logical_id(owner)[0], challenge[0]};
        auto consent = session.verify_owner_proof(owner, challenge, proof);
        auto consumed = BaselineOwnerRosterVerifiedBridge::consume(
            std::move(consent));
        assert(consumed.owner() == owner);
        assert(consumed.logical_owner_identity() == logical_id(owner));
        refuses([&] {
            (void)BaselineOwnerRosterVerifiedBridge::consume(
                std::move(consent));
        });
    }
    auto verified = session.finish();
    const std::array<LogicalOwnerIdentity, 3> expected{
        logical_id(0), logical_id(1), logical_id(2)};
    assert(verified.test_only_logical_owner_ids() == expected);
    auto consumed = BaselineOwnerRosterVerifiedBridge::consume(
        std::move(verified));
    assert(consumed.public_receipt().round == 1);
    assert(consumed.public_receipt().role == 0);
    assert(consumed.logical_owner_ids() == expected);
    refuses([&] {
        (void)BaselineOwnerRosterVerifiedBridge::consume(
            std::move(verified));
    });
}

void hidden_candidate_has_no_roster() {
    auto registry = std::make_shared<MemoryReplayRegistry>();
    auto selected = FreshOwnerTrialIssuanceBridge::join_exact_three(
        hidden_owners(), replay_guard(registry), {});
    auto split = FreshOwnerTrialIssuanceBridge::split(std::move(selected));
    assert(split.take_round(1).public_receipt().classification ==
           CaptureClassification::HiddenCandidate);
    assert(split.take_round(2).public_receipt().classification ==
           CaptureClassification::HiddenCandidate);
    refuses([&] { (void)split.take_baseline_roster(); });
}

void round2_requires_accepted_round1_history_gate() {
    auto value = receipt(0);
    value.rounds[1].history_gate_identity = {};
    refuses([&] {
        (void)OwnerLocalIssuanceAuthority::test_only_mint(
            std::move(value),
            std::make_shared<TestVerifier>(logical_id(0)), id(0x400));
    });
}

void durable_replay_refuses() {
    auto registry = std::make_shared<MemoryReplayRegistry>();
    auto first = FreshOwnerTrialIssuanceBridge::join_exact_three(
        owners(), replay_guard(registry), id(0x600));
    assert(first.public_receipt().issuance_identity != Digest{});
    refuses([&] {
        (void)FreshOwnerTrialIssuanceBridge::join_exact_three(
            owners(), replay_guard(registry), id(0x600));
    });
}

void transactional_commit_retains_closed_sum() {
    PreidentityRoleProgram program;
    auto outcome = transactional_outcome(
        program,
        replay::OwnerReplayBackendCommitDisposition::Committed);
    assert(FreshOwnerTransactionalIssuanceTestBridge::inspect(outcome) ==
           TestFreshOwnerTransactionalIssuanceOutcome::Committed);
    FreshOwnerTransactionalIssuanceOutcomeAuthority retained(
        std::move(outcome));
    assert(FreshOwnerTransactionalIssuanceTestBridge::inspect(outcome) ==
           TestFreshOwnerTransactionalIssuanceOutcome::Invalid);
    assert(FreshOwnerTransactionalIssuanceTestBridge::inspect(retained) ==
           TestFreshOwnerTransactionalIssuanceOutcome::Committed);
}

void transactional_unavailable_retains_stop_sum() {
    PreidentityRoleProgram program;
    auto outcome = transactional_outcome(
        program,
        replay::OwnerReplayBackendCommitDisposition::
            AmbiguousAfterWrite);
    assert(FreshOwnerTransactionalIssuanceTestBridge::inspect(outcome) ==
           TestFreshOwnerTransactionalIssuanceOutcome::UnavailableStop);
    FreshOwnerTransactionalIssuanceOutcomeAuthority retained(
        std::move(outcome));
    assert(FreshOwnerTransactionalIssuanceTestBridge::inspect(outcome) ==
           TestFreshOwnerTransactionalIssuanceOutcome::Invalid);
    assert(FreshOwnerTransactionalIssuanceTestBridge::inspect(retained) ==
           TestFreshOwnerTransactionalIssuanceOutcome::UnavailableStop);
}

void transactional_post_prepare_path_allocates_nothing() {
    PreidentityRoleProgram program;
    auto outcome = transactional_outcome(
        program, replay::OwnerReplayBackendCommitDisposition::Committed,
        true);
    assert(FreshOwnerTransactionalIssuanceTestBridge::inspect(outcome) ==
           TestFreshOwnerTransactionalIssuanceOutcome::Committed);
}

void arm_allocation_failure() { fail_allocations = true; }

void issuance_split_postclaim_path_allocates_nothing() {
    auto registry = std::make_shared<MemoryReplayRegistry>();
    auto selected = FreshOwnerTrialIssuanceBridge::join_exact_three(
        owners(), replay_guard(registry), id(0x600));
    FreshOwnerTrialIssuanceBridge::test_only_set_split_postprepare_hook(
        arm_allocation_failure);
    try {
        auto split = FreshOwnerTrialIssuanceBridge::split(
            std::move(selected));
        fail_allocations = false;
        FreshOwnerTrialIssuanceBridge::test_only_set_split_postprepare_hook(
            nullptr);
        assert(split.take_round(1).public_receipt().round == 1);
        assert(split.take_round(2).public_receipt().round == 2);
        (void)split.take_baseline_roster();
    } catch (...) {
        fail_allocations = false;
        FreshOwnerTrialIssuanceBridge::test_only_set_split_postprepare_hook(
            nullptr);
        throw;
    }
}

void mixed_controller_tls_and_logical_owner_refuse() {
    auto registry = std::make_shared<MemoryReplayRegistry>();
    auto one = receipt(1);
    one.controller_build_identity = id(0x999);
    std::array<OwnerLocalIssuanceAuthority, 3> mixed{
        owner_authority(0), mint(std::move(one), logical_id(1), id(0x401)),
        owner_authority(2)};
    refuses([&] {
        (void)FreshOwnerTrialIssuanceBridge::join_exact_three(
            std::move(mixed), replay_guard(registry), id(0x600));
    });

    auto tls = receipt(0);
    tls.rounds[1].owner_tls_spki_identity =
        tls.rounds[0].owner_tls_spki_identity;
    refuses([&] {
        (void)mint(std::move(tls), logical_id(0), id(0x400));
    });

    std::array<OwnerLocalIssuanceAuthority, 3> duplicate_owner{
        owner_authority(0), mint(receipt(1), logical_id(0), id(0x401)),
        owner_authority(2)};
    refuses([&] {
        (void)FreshOwnerTrialIssuanceBridge::join_exact_three(
            std::move(duplicate_owner), replay_guard(registry), id(0x600));
    });
}

void known_tombstones_refuse() {
    auto aborted = receipt(0);
    aborted.run = identity_registry::mandatory_aborted_run();
    refuses([&] {
        (void)mint(std::move(aborted), logical_id(0), id(0x400));
    });

    auto consumed = receipt(0);
    consumed.root_identity = mandatory_consumed_owner_root_identity();
    refuses([&] {
        (void)mint(std::move(consumed), logical_id(0), id(0x400));
    });

    auto registry = std::make_shared<MemoryReplayRegistry>();
    refuses([&] {
        (void)FreshOwnerTrialIssuanceBridge::join_exact_three(
            owners(), replay_guard(registry),
            identity_registry::mandatory_aborted_run());
    });

    refuses([&] {
        (void)OwnerIssuanceReplayGuardAuthority::test_only_mint(
            PublicOwnerIssuanceReplayPolicy{
                .authority_identity = id(0x500),
                .policy_identity = mandatory_consumed_owner_root_identity(),
                .permission_separated = true,
                .monotonic = true,
                .child_path_exposed = false,
                .child_fd_exposed = false,
            }, registry);
    });
}

BaselineOwnerRosterReceiverSession receiver_session() {
    auto registry = std::make_shared<MemoryReplayRegistry>();
    auto selected = FreshOwnerTrialIssuanceBridge::join_exact_three(
        owners(), replay_guard(registry), id(0x600));
    auto split = FreshOwnerTrialIssuanceBridge::split(std::move(selected));
    (void)split.take_round(1);
    (void)split.take_round(2);
    auto receivers = BaselineOwnerRosterBridge::split(
        split.take_baseline_roster());
    return BaselineOwnerRosterReceiverBridge::consume(
        receivers.take(2, 1),
        CaptureClassification::ExplicitOwnerPublicEffectsBaseline,
        2, 1, id(8), id(9), id(0x700));
}

void wrong_owner_proof_poisons_session() {
    auto session = receiver_session();
    const std::array<unsigned char, 2> challenge{0x88, 0x55};
    const std::array<unsigned char, 2> wrong{0xff, 0x88};
    refuses([&] { (void)session.verify_owner_proof(0, challenge, wrong); });
    const std::array<unsigned char, 2> right{logical_id(0)[0], 0x88};
    refuses([&] { (void)session.verify_owner_proof(0, challenge, right); });
    refuses([&] { (void)session.finish(); });
}

void source_status_stays_closed() {
    const auto status = fresh_owner_issuance_source_status();
    assert(status.status == "SOURCE_ONLY_CONFIGURED0");
    assert(status.exact_three_owner_process_authorities);
    assert(status.two_fresh_round_contracts);
    assert(status.round2_history_metadata_bound);
    assert(!status.controller_reads_or_hashes_private_body);
    assert(!status.stable_logical_owner_ids_public);
    assert(status.baseline_roster_possession_verification);
    assert(status.permission_separated_replay_registry_interface);
    assert(!status.authenticated_owner_process_adapter);
    assert(!status.private_lifecycle_owner_process_adapter);
    assert(!status.round2_accepted_history_capability_gate);
    assert(!status.permission_separated_replay_registry_minter);
    assert(!status.selected_driver_round_adapter);
    assert(!status.registered_driver_configured);
    assert(!status.launch_authorized);
}

} // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    const std::string_view scenario(argv[1]);
    if (scenario == "happy") happy_join_and_split();
    else if (scenario == "hidden") hidden_candidate_has_no_roster();
    else if (scenario == "causal")
        round2_requires_accepted_round1_history_gate();
    else if (scenario == "replay") durable_replay_refuses();
    else if (scenario == "transactional-commit")
        transactional_commit_retains_closed_sum();
    else if (scenario == "transactional-stop")
        transactional_unavailable_retains_stop_sum();
    else if (scenario == "transactional-noalloc")
        transactional_post_prepare_path_allocates_nothing();
    else if (scenario == "split-noalloc")
        issuance_split_postclaim_path_allocates_nothing();
    else if (scenario == "mixed")
        mixed_controller_tls_and_logical_owner_refuse();
    else if (scenario == "tombstones") known_tombstones_refuse();
    else if (scenario == "proof") wrong_owner_proof_poisons_session();
    else if (scenario == "status") source_status_stays_closed();
    else return 2;
}
