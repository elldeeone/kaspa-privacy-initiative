#include "../registered_driver_bridge.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <concepts>
#include <filesystem>
#include <fcntl.h>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using namespace kpi::mpc::financial;
using namespace kpi::mpc::financial::attempt_supervisor;
using namespace kpi::mpc::financial::registered_driver;

namespace {
constexpr unsigned TEST_ROLE = 2;
constexpr std::string_view TRIAL_UUID =
    "11111111-1111-4111-8111-111111111111";
template<class T> concept HasRegistryAccessor = requires(T& value) {
    value.registry();
};
template<class T> concept HasAnchorAccessor = requires(T& value) {
    value.anchor();
};
Digest id(unsigned value) {
    Digest result{};
    result[0] = static_cast<unsigned char>(value);
    result[1] = static_cast<unsigned char>(value >> 8);
    result[31] = static_cast<unsigned char>(value ^ 0x5aU);
    return result;
}

identity_registry::Authority authority() {
    return identity_registry::Authority{
        .registration = id(1), .service = id(2), .source = id(3),
        .build = id(4),
        .aborted_runs = {identity_registry::mandatory_aborted_run()},
    };
}

Selection selection(unsigned base = 0x100) {
    return Selection{
        .run = id(base),
        .trial = RegisteredCapturePlanRosterBridge::trial_identity(
            TRIAL_UUID),
        .attempt = RegisteredCapturePlanRosterBridge::attempt_identity(
            "123e4567-e89b-42d3-a456-426614174000"),
        .cohort = id(base + 3), .accepted_head = id(base + 4),
        .owner_contracts = {id(base + 5), id(base + 6), id(base + 7)},
    };
}

struct Root {
    std::filesystem::path path, journal, anchor;
    Root() {
        std::array<char, 80> pattern{};
        const std::string value = "/tmp/kpb-registered-driver-XXXXXX";
        std::copy(value.begin(), value.end(), pattern.begin());
        const auto made = ::mkdtemp(pattern.data());
        assert(made != nullptr);
        path = made;
        journal = path / "journal";
        anchor = path / "anchor";
        assert(std::filesystem::create_directory(journal));
        assert(std::filesystem::create_directory(anchor));
        assert(::chmod(journal.c_str(), 0700) == 0);
        assert(::chmod(anchor.c_str(), 0700) == 0);
    }
    ~Root() { std::filesystem::remove_all(path); }
};

class FixedRole0CaptureSinks final {
    static constexpr std::array<int, 2> targets_{20, 22};
    std::array<int, 2> saved_{{-1, -1}};
public:
    FixedRole0CaptureSinks() {
        const int sink = ::open("/dev/null", O_WRONLY | O_CLOEXEC);
        assert(sink >= 0);
        for (std::size_t index = 0; index < targets_.size(); ++index) {
            errno = 0;
            if (::fcntl(targets_[index], F_GETFD) >= 0)
                saved_[index] = ::fcntl(
                    targets_[index], F_DUPFD_CLOEXEC, 64);
            else
                assert(errno == EBADF);
            assert(::dup2(sink, targets_[index]) == targets_[index]);
        }
        assert(::close(sink) == 0);
    }
    FixedRole0CaptureSinks(const FixedRole0CaptureSinks&) = delete;
    ~FixedRole0CaptureSinks() {
        for (std::size_t index = 0; index < targets_.size(); ++index) {
            (void)::close(targets_[index]);
            if (saved_[index] >= 0) {
                assert(::dup2(saved_[index], targets_[index]) ==
                       targets_[index]);
                assert(::close(saved_[index]) == 0);
            }
        }
    }
};

class MemoryAnchor final : public ExternalMonotonicAnchor {
    std::mutex mutex_;
    ExternalAnchorSnapshot state_;
public:
    explicit MemoryAnchor(const identity_registry::PublicSnapshot& state)
        : state_{state.authority_identity, state.sequence, state.checkpoint} {}
    ExternalAnchorSnapshot snapshot() override {
        std::lock_guard guard(mutex_);
        return state_;
    }
    void compare_and_advance(const ExternalAnchorSnapshot& expected,
                             const ExternalAnchorSnapshot& next) override {
        std::lock_guard guard(mutex_);
        if (state_ != expected) throw identity_registry::Refused();
        state_ = next;
    }
};

Proposal proposal(unsigned role, const Digest& authority_identity,
                  const Digest& supervisor_session,
                  const Selection& selected) {
    return Proposal::test_only_mint(
        role, authority_identity, supervisor_session, id(0x80 + role),
        AttemptLineageCommitment::test_only_mint(
            selected.run, selected.trial, selected.attempt, selected.cohort),
        DirectAcceptedHeadCommitment::test_only_mint(selected.accepted_head),
        CanonicalOwnerContractsCommitment::test_only_mint(
            selected.owner_contracts));
}

SupervisorAnchorPolicy policy(identity_registry::Registry& registry) {
    return SupervisorAnchorPolicy::test_only_mint(
        PublicAnchorPolicy{
            .policy_identity = id(0x60), .permission_separated = true,
            .monotonic = true, .child_path_exposed = false,
            .child_fd_exposed = false,
        },
        std::make_shared<MemoryAnchor>(registry.snapshot()));
}

PartyApproval approval(identity_registry::Registry& registry,
                       const Digest& session, const Selection& selected,
                       Proposal& local,
                       unsigned selected_role = TEST_ROLE) {
    const auto authority_identity = registry.snapshot().authority_identity;
    Supervisor supervisor(registry, session, policy(registry));
    std::array<Proposal, 3> proposals{
        proposal(0, authority_identity, session, selected),
        proposal(1, authority_identity, session, selected),
        proposal(2, authority_identity, session, selected),
    };
    for (const auto& item : proposals) supervisor.submit(item);
    auto batch = supervisor.approve();
    for (unsigned role = 0; role < 3; ++role) {
        const auto preview = batch.preview(role, proposals[role].party_session());
        batch.acknowledge(role, proposals[role].party_session(),
                          preview.approval_identity);
    }
    assert(batch.activated());
    assert(selected_role < 3);
    local = proposals[selected_role];
    return batch.take(
        selected_role, proposals[selected_role].party_session());
}

template<class Callable>
void expect_refusal(Callable&& callable) {
    bool refused = false;
    try { callable(); }
    catch (const identity_registry::Refused&) { refused = true; }
    assert(refused);
}

CompiledDriverSelection configuration(
    const identity_registry::Registry& registry, const Selection& selected,
    unsigned role = TEST_ROLE) {
    return CompiledDriverSelection::test_only_mint(PublicDriverSelection{
        .role = role,
        .authority_identity = registry.snapshot().authority_identity,
        .selection_identity = identity_registry::selection_identity(selected),
        .service_identity = id(0x201), .source_identity = id(0x202),
        .build_identity = id(0x203), .roster_identity = id(0x204),
        .capture_source_identity = id(0x205),
        .capture_build_identity = id(0x206),
        .capture_launcher_identity = id(0x207),
        .model_preimage_identity = id(0x208),
        .query_store_preimage_identity = id(0x209),
        .scalar_capture_manifest_identity = identity_registry::unhex(
            "5e6903569bc71cbfb5549b369b79a19ecda6686dc4ab25fca0d161c6e1527b6b"),
        .owner_port = 32100, .multiplication_batch = 4096,
    });
}

CapturePlanAuthority capture_plan(
        const Selection& selected,
        CaptureClassification classification =
            CaptureClassification::HiddenCandidate,
        Digest trial_override = {}, unsigned role = TEST_ROLE) {
    const auto trial = trial_override == Digest{}
        ? selected.trial : trial_override;
    return CapturePlanAuthority::test_only_session_residual(PublicCapturePlan{
        .classification = classification,
        .round = 1,
        .capture_trial_id = std::string(TRIAL_UUID),
        .capture_attempt_id = "123e4567-e89b-42d3-a456-426614174000",
        .capture_identity = "123e4567-e89b-42d3-b456-426614174001",
        .run = selected.run, .trial = trial,
        .attempt = selected.attempt,
        .cohort = selected.cohort, .source_identity = id(0x205),
        .build_identity = id(0x206), .launcher_identity = id(0x207),
        .model_preimage_identity = id(0x208),
        .query_store_preimage_identity = id(0x209),
        .scalar_capture_manifest_identity = identity_registry::unhex(
            "5e6903569bc71cbfb5549b369b79a19ecda6686dc4ab25fca0d161c6e1527b6b"),
        .fixed_fds = {20, 21, 22, 23, 24, 25, 26, 27, 28, 29},
    }, role);
}

void complete_authority_chain() {
    Root root;
    auto registry = identity_registry::Registry::initialize_fresh_unfunded(
        root.journal, root.anchor, authority());
    const auto selected = selection();
    const auto session = id(0x70);
    Proposal local = proposal(
        TEST_ROLE, registry.snapshot().authority_identity, session, selected);
    auto party = approval(registry, session, selected, local);

    const auto config = configuration(registry, selected);
    auto capture = capture_plan(selected);
    auto before_lock = DriverAttempt::test_only_admit(
        config, std::move(capture), std::move(party), local);
    before_lock.test_only_recheck_before_lock(
        DirectAcceptedHeadCommitment::test_only_mint(selected.accepted_head));
    auto active = before_lock.test_only_after_durable_lock(
        DirectAcceptedHeadCommitment::test_only_mint(selected.accepted_head),
        DurableLockCommitment::test_only_mint(
            TEST_ROLE, identity_registry::selection_identity(selected),
            selected.accepted_head, id(0x301)));
    assert(active->public_receipt().classification ==
           CaptureClassification::HiddenCandidate);
    const auto intake = active->test_only_consume_owner_intake(TEST_ROLE);
    assert(intake.accepted_head == selected.accepted_head);

    std::vector<unsigned char> projection(10685, 0x41);
    active->test_only_capture_lifecycle(projection, 1024);
    const auto projection_identity = identity_registry::digest(projection);

    auto egress = VerifiedEgressAuthority::test_only_mint(PublicVerifiedEgress{
        .binding_identity = id(0x301), .effects_identity = id(0x402),
        .core_identity = id(0x403), .proof_identity = id(0x404),
        .projection_identity = projection_identity,
    });
    const auto barrier = id(0x405);
    active->test_only_authorize_release(std::move(egress), barrier, 1001);
    const auto completed = active->complete_egress();
    assert(completed.public_receipt().role == TEST_ROLE);
    assert(completed.public_receipt().accepted_head == selected.accepted_head);
    assert(completed.public_receipt().attempt_identity ==
           active->public_receipt().attempt_identity);
    assert(completed.public_receipt().authorization_identity ==
           active->public_receipt().authorization_identity);
    assert(completed.public_receipt().owner_contracts ==
           selected.owner_contracts);
    assert(completed.public_receipt().projection_identity == projection_identity);
    assert(completed.public_receipt().full_cohort_barrier_identity == barrier);
    assert(completed.public_receipt()
               .full_cohort_barrier_observed_monotonic_ns == 1001);
    assert(completed.public_receipt().completion_identity != Digest{});
}

void authority_bypass_replay() {
    for (unsigned mutation = 0; mutation < 7; ++mutation) {
        Root root;
        auto registry = identity_registry::Registry::initialize_fresh_unfunded(
            root.journal, root.anchor, authority());
        const auto selected = selection(0x500 + mutation * 0x20);
        const auto session = id(0x700 + mutation);
        Proposal local = proposal(
            TEST_ROLE, registry.snapshot().authority_identity, session, selected);
        auto party = approval(registry, session, selected, local);
        auto config = configuration(registry, selected);
        auto capture = [&]() -> CapturePlanAuthority {
            if (mutation == 3)
                return CapturePlanAuthority::test_only_session_residual(PublicCapturePlan{
                .classification = CaptureClassification::HiddenCandidate,
                .round = 0,
                .capture_trial_id = std::string(TRIAL_UUID),
                .capture_attempt_id = "123e4567-e89b-42d3-a456-426614174000",
                .capture_identity = "123e4567-e89b-42d3-b456-426614174001",
                .run = selected.run, .trial = selected.trial,
                .attempt = selected.attempt,
                .cohort = selected.cohort, .source_identity = id(0x205),
                .build_identity = id(0x206), .launcher_identity = id(0x207),
                .fixed_fds = {20, 21, 22, 23, 24, 25, 26, 27, 28, 29},
                }, TEST_ROLE);
            if (mutation == 4)
                return CapturePlanAuthority::test_only_session_residual(PublicCapturePlan{
                    .classification = CaptureClassification::HiddenCandidate,
                    .round = 1,
                    .capture_trial_id = std::string(TRIAL_UUID),
                    .capture_attempt_id = "123E4567-E89B-42D3-A456-426614174000",
                    .capture_identity = "123e4567-e89b-42d3-b456-426614174001",
                    .run = selected.run, .trial = selected.trial,
                    .attempt = selected.attempt,
                    .cohort = selected.cohort, .source_identity = id(0x205),
                    .build_identity = id(0x206), .launcher_identity = id(0x207),
                    .fixed_fds = {20, 21, 22, 23, 24, 25, 26, 27, 28, 29},
                }, TEST_ROLE);
            if (mutation == 5)
                return CapturePlanAuthority::test_only_session_residual(PublicCapturePlan{
                    .classification = static_cast<CaptureClassification>(0),
                    .round = 1,
                    .capture_trial_id = std::string(TRIAL_UUID),
                    .capture_attempt_id = "123e4567-e89b-42d3-a456-426614174000",
                    .capture_identity = "123e4567-e89b-42d3-b456-426614174001",
                    .run = selected.run, .trial = selected.trial,
                    .attempt = selected.attempt,
                    .cohort = selected.cohort, .source_identity = id(0x205),
                    .build_identity = id(0x206), .launcher_identity = id(0x207),
                    .fixed_fds = {20, 21, 22, 23, 24, 25, 26, 27, 28, 29},
                }, TEST_ROLE);
            if (mutation == 6)
                return capture_plan(
                    selected, CaptureClassification::HiddenCandidate,
                    id(0xf00d));
            return capture_plan(selected);
        }();
        auto head = selected.accepted_head;
        if (mutation == 0)
            config = CompiledDriverSelection::test_only_mint(
                PublicDriverSelection{
                    .role = TEST_ROLE, .authority_identity = id(0xdead),
                    .selection_identity = identity_registry::selection_identity(selected),
                    .service_identity = id(0x201), .source_identity = id(0x202),
                    .build_identity = id(0x203), .roster_identity = id(0x204),
                    .capture_source_identity = id(0x205),
                    .capture_build_identity = id(0x206),
                    .capture_launcher_identity = id(0x207),
                    .owner_port = 32100, .multiplication_batch = 4096,
                });
        if (mutation == 1) head = id(0xbeef);
        if (mutation == 2) {
            auto changed = selected;
            changed.owner_contracts[2] = id(0xcafe);
            local = proposal(TEST_ROLE, registry.snapshot().authority_identity,
                             session, changed);
        }
        if (mutation == 1) {
            auto attempt = DriverAttempt::test_only_admit(
                config, std::move(capture), std::move(party), local);
            expect_refusal([&] {
                attempt.test_only_recheck_before_lock(
                    DirectAcceptedHeadCommitment::test_only_mint(head));
            });
        } else {
            expect_refusal([&] {
                (void)DriverAttempt::test_only_admit(
                    config, std::move(capture), std::move(party), local);
            });
        }
    }

    Root root;
    auto registry = identity_registry::Registry::initialize_fresh_unfunded(
        root.journal, root.anchor, authority());
    const auto selected = selection(0x900);
    const auto session = id(0x970);
    Proposal local = proposal(
        TEST_ROLE, registry.snapshot().authority_identity, session, selected);
    auto party = approval(registry, session, selected, local);
    auto capture = capture_plan(selected);
    auto attempt = DriverAttempt::test_only_admit(
        configuration(registry, selected), std::move(capture),
        std::move(party), local);
    expect_refusal([&] {
        (void)attempt.test_only_after_durable_lock(
            DirectAcceptedHeadCommitment::test_only_mint(selected.accepted_head),
            DurableLockCommitment::test_only_mint(
                TEST_ROLE, identity_registry::selection_identity(selected),
                selected.accepted_head, id(0x900)));
    });

    // A separate attempt proves that the first recheck is mandatory and
    // one-shot before any post-LOCK authority can be consumed.
    Root root2;
    auto registry2 = identity_registry::Registry::initialize_fresh_unfunded(
        root2.journal, root2.anchor, authority());
    const auto selected2 = selection(0xa00);
    const auto session2 = id(0xa70);
    Proposal local2 = proposal(
        TEST_ROLE, registry2.snapshot().authority_identity, session2, selected2);
    auto party2 = approval(registry2, session2, selected2, local2);
    auto capture2 = capture_plan(selected2);
    auto checked = DriverAttempt::test_only_admit(
        configuration(registry2, selected2), std::move(capture2),
        std::move(party2), local2);
    checked.test_only_recheck_before_lock(
        DirectAcceptedHeadCommitment::test_only_mint(selected2.accepted_head));
    expect_refusal([&] {
        checked.test_only_recheck_before_lock(
            DirectAcceptedHeadCommitment::test_only_mint(selected2.accepted_head));
    });

    Root root3;
    auto registry3 = identity_registry::Registry::initialize_fresh_unfunded(
        root3.journal, root3.anchor, authority());
    const auto selected3 = selection(0xb00);
    const auto session3 = id(0xb70);
    Proposal local3 = proposal(
        TEST_ROLE, registry3.snapshot().authority_identity, session3, selected3);
    auto party3 = approval(registry3, session3, selected3, local3);
    auto capture3 = capture_plan(selected3);
    auto stale_after_lock = DriverAttempt::test_only_admit(
        configuration(registry3, selected3), std::move(capture3),
        std::move(party3), local3);
    stale_after_lock.test_only_recheck_before_lock(
        DirectAcceptedHeadCommitment::test_only_mint(selected3.accepted_head));
    expect_refusal([&] {
        (void)stale_after_lock.test_only_after_durable_lock(
            DirectAcceptedHeadCommitment::test_only_mint(id(0xbad)),
            DurableLockCommitment::test_only_mint(
                TEST_ROLE, identity_registry::selection_identity(selected3),
                selected3.accepted_head, id(0x901)));
    });
    expect_refusal([&] {
        (void)stale_after_lock.test_only_after_durable_lock(
            DirectAcceptedHeadCommitment::test_only_mint(selected3.accepted_head),
            DurableLockCommitment::test_only_mint(
                TEST_ROLE, identity_registry::selection_identity(selected3),
                selected3.accepted_head, id(0x902)));
    });
}

template<class Callable>
void with_active(
        unsigned base, bool claim_intake, Callable&& callable,
        CaptureClassification classification =
            CaptureClassification::HiddenCandidate,
        unsigned role = TEST_ROLE) {
    Root root;
    auto registry = identity_registry::Registry::initialize_fresh_unfunded(
        root.journal, root.anchor, authority());
    const auto selected = selection(base);
    const auto session = id(base + 0x10);
    Proposal local = proposal(
        role, registry.snapshot().authority_identity, session, selected);
    auto party = approval(registry, session, selected, local, role);
    auto capture = capture_plan(selected, classification, {}, role);
    auto attempt = DriverAttempt::test_only_admit(
        configuration(registry, selected, role), std::move(capture),
        std::move(party), local);
    attempt.test_only_recheck_before_lock(
        DirectAcceptedHeadCommitment::test_only_mint(selected.accepted_head));
    auto active = attempt.test_only_after_durable_lock(
        DirectAcceptedHeadCommitment::test_only_mint(selected.accepted_head),
        DurableLockCommitment::test_only_mint(
            role, identity_registry::selection_identity(selected),
            selected.accepted_head, id(base + 0x11)));
    if (claim_intake)
        (void)active->test_only_consume_owner_intake(role);
    callable(*active);
}

VerifiedEgressAuthority egress(Digest binding,
                               Digest projection = id(0xa05)) {
    return VerifiedEgressAuthority::test_only_mint(PublicVerifiedEgress{
        .binding_identity = binding, .effects_identity = id(0xa02),
        .core_identity = id(0xa03), .proof_identity = id(0xa04),
        .projection_identity = projection,
    });
}

void capture_completion_gate() {
    with_active(0xb00, false, [](auto& active) {
        auto proof = egress(active.public_receipt().durable_lock);
        expect_refusal([&] {
            active.test_only_authorize_release(
                std::move(proof), id(0xb05), 1002);
        });
        expect_refusal([&] {
            (void)active.test_only_consume_owner_intake(TEST_ROLE);
        });
    });
    with_active(0xc00, true, [](auto& active) {
        std::vector<unsigned char> projection(10685, 0x42);
        active.test_only_capture_lifecycle(projection, 1024);
        auto proof = egress(active.public_receipt().durable_lock,
                            id(0xc05));
        expect_refusal([&] {
            active.test_only_authorize_release(
                std::move(proof), id(0xc06), 1003);
        });
    });
    with_active(0xd80, true, [](auto& active) {
        std::vector<unsigned char> projection(10685, 0x44);
        active.test_only_capture_lifecycle(projection, 1024);
        const auto projection_identity = identity_registry::digest(projection);
        auto proof = egress(id(0xdead), projection_identity);
        expect_refusal([&] {
            active.test_only_authorize_release(
                std::move(proof), id(0xd86), 1004);
        });
    });
    with_active(0xe00, true, [](auto& active) {
        std::vector<unsigned char> projection(10685, 0x45);
        active.test_only_capture_lifecycle(projection, 1024);
        const auto projection_identity = identity_registry::digest(projection);
        auto first_proof = egress(active.public_receipt().durable_lock,
                                  projection_identity);
        active.test_only_authorize_release(
            std::move(first_proof), id(0xe06), 1005);
        const auto result = active.complete_egress();
        assert(result.public_receipt().completion_identity != Digest{});
        assert(result.public_receipt().projection_identity ==
               projection_identity);
        expect_refusal([&] {
            (void)active.complete_egress();
        });
        expect_refusal([&] {
            (void)active.claim_baseline_effects();
        });
    });
    with_active(0xf00, true, [](auto& active) {
        std::vector<unsigned char> projection(10685, 0x46);
        active.test_only_capture_lifecycle(projection, 1024);
        auto claim = active.claim_baseline_effects();
        const auto receipt = claim.consume();
        assert(receipt.classification ==
               CaptureClassification::ExplicitOwnerPublicEffectsBaseline);
        assert(receipt.owner_contracts == selection(0xf00).owner_contracts);
        expect_refusal([&] { (void)claim.consume(); });
        expect_refusal([&] { (void)active.claim_baseline_effects(); });
        const auto projection_identity = identity_registry::digest(projection);
        auto proof = egress(active.public_receipt().durable_lock,
                            projection_identity);
        active.test_only_authorize_release(
            std::move(proof), id(0xf06), 1006);
        const auto completed = active.complete_egress();
        assert(completed.public_receipt().projection_identity ==
               projection_identity);
        expect_refusal([&] { (void)active.claim_baseline_effects(); });
    }, CaptureClassification::ExplicitOwnerPublicEffectsBaseline);
    {
        FixedRole0CaptureSinks sinks;
        with_active(0xf80, true, [](auto& active) {
            std::vector<unsigned char> projection(10685, 0x47);
            active.test_only_capture_lifecycle(projection, 1024);
            const auto projection_identity =
                identity_registry::digest(projection);
            auto proof = egress(active.public_receipt().durable_lock,
                                projection_identity);
            active.test_only_authorize_release(
                std::move(proof), id(0xf86), 1007);
            expect_refusal([&] {
                (void)active.complete_egress();
            });
        }, CaptureClassification::HiddenCandidate, 0);
    }
}

void source_boundary() {
    static_assert(!std::copy_constructible<DriverAttempt>);
    static_assert(!std::copy_constructible<AuthorizedDriverAttempt>);
    static_assert(!std::copy_constructible<CapturePlanAuthority>);
    static_assert(!std::copy_constructible<PartyDriverCompletionAuthority>);
    static_assert(!std::constructible_from<VerifiedEgressAuthority,
                                           PublicVerifiedEgress>);
    static_assert(!std::constructible_from<PartyDriverCompletionAuthority,
                                           PublicPartyDriverCompletion>);
    static_assert(!std::default_initializable<DriverAttempt>);
    static_assert(!std::default_initializable<AuthorizedDriverAttempt>);
    static_assert(!std::default_initializable<
        AuthorizedDriverAttempt::BaselineEffectsClaim>);
    static_assert(!std::default_initializable<OuterSupervisorAuthority>);
    static_assert(!std::copy_constructible<OuterSupervisorAuthority>);
    static_assert(!HasRegistryAccessor<OuterSupervisorAuthority>);
    static_assert(!HasAnchorAccessor<OuterSupervisorAuthority>);
    const auto status = registered_driver::source_status();
    assert(status.schema == "kpb-registered-driver-bridge-source-only/v1");
    assert(status.status == "UNQUALIFIED_SOURCE_ONLY");
    assert(!status.accepts_argv_or_environment);
    assert(status.registry_lifetime_owned_by_driver);
    assert(status.docker_anchor_client_bridge);
    assert(!status.party_can_access_registry_anchor_path_or_fd);
    assert(status.capture_classification_bound);
    assert(status.p1_capture_plan_split_authority);
    assert(!status.p1_capturing_player_callsite_integration);
    assert(!status.authenticated_per_role_ipc_delivery);
    assert(status.durable_lock_minted_from_locked_attempt);
    assert(status.genuine_head_and_owner_factory_integrated);
    assert(status.construct_registered_integration);
    assert(status.proof_verification_integration);
    assert(status.verified_release_integration);
    assert(status.party_egress_completion_authority);
    assert(!status.actual_capture_completion_integration);
    assert(!status.global_capture_supervisor_integration);
    assert(!status.parent_durable_completion_integration);
    assert(!status.downstream_completion_authority);
    assert(!status.downstream_completion_integration);
    assert(!status.registered_driver_configured);
    assert(!status.launch_authorized);
}
} // namespace

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    const std::string scenario = argv[1];
    if (scenario == "complete-authority-chain") {
        complete_authority_chain();
        return 0;
    }
    if (scenario == "authority-bypass-replay") {
        authority_bypass_replay();
        return 0;
    }
    if (scenario == "capture-completion-gate") {
        capture_completion_gate();
        return 0;
    }
    if (scenario == "source-boundary") {
        source_boundary();
        return 0;
    }
    return 2;
}
