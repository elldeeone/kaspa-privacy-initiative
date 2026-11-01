#include "../registered_attempt_supervisor.hpp"

#include <array>
#include <atomic>
#include <cassert>
#include <concepts>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace kpi::mpc::financial;
using namespace kpi::mpc::financial::attempt_supervisor;

namespace {
Digest id(unsigned value) {
    Digest result{};
    result[0] = static_cast<unsigned char>(value);
    result[1] = static_cast<unsigned char>(value >> 8);
    result[31] = static_cast<unsigned char>(value ^ 0x5aU);
    return result;
}

identity_registry::Authority authority() {
    return identity_registry::Authority{
        .registration = id(1), .service = id(2), .source = id(3), .build = id(4),
        .aborted_runs = {identity_registry::mandatory_aborted_run()},
    };
}

Selection selection(unsigned base = 0x100) {
    return Selection{
        .run = id(base), .trial = id(base + 1), .attempt = id(base + 2),
        .cohort = id(base + 3), .accepted_head = id(base + 4),
        .owner_contracts = {id(base + 5), id(base + 6), id(base + 7)},
    };
}

struct Root {
    std::filesystem::path path, journal, anchor;
    Root() {
        std::array<char, 80> pattern{};
        const std::string value = "/tmp/kpb-attempt-supervisor-XXXXXX";
        std::copy(value.begin(), value.end(), pattern.begin());
        const auto made = ::mkdtemp(pattern.data());
        assert(made != nullptr);
        path = made; journal = path / "journal"; anchor = path / "anchor";
        assert(std::filesystem::create_directory(journal));
        assert(std::filesystem::create_directory(anchor));
        assert(::chmod(journal.c_str(), 0700) == 0);
        assert(::chmod(anchor.c_str(), 0700) == 0);
    }
    ~Root() { std::filesystem::remove_all(path); }
};

class MemoryAnchor final : public ExternalMonotonicAnchor {
public:
    enum class Failure { None, BeforeAdvance, AfterAdvance };
private:
    std::mutex mutex_;
    ExternalAnchorSnapshot state_;
    Failure failure_;
public:
    explicit MemoryAnchor(const identity_registry::PublicSnapshot& state,
                          Failure failure = Failure::None)
        : state_{state.authority_identity, state.sequence, state.checkpoint},
          failure_(failure) {}
    explicit MemoryAnchor(ExternalAnchorSnapshot state,
                          Failure failure = Failure::None)
        : state_(state), failure_(failure) {}
    ExternalAnchorSnapshot snapshot() override {
        std::lock_guard guard(mutex_);
        return state_;
    }
    void compare_and_advance(const ExternalAnchorSnapshot& expected,
                             const ExternalAnchorSnapshot& next) override {
        std::lock_guard guard(mutex_);
        if (state_ != expected || failure_ == Failure::BeforeAdvance)
            throw identity_registry::Refused();
        state_ = next;
        if (failure_ == Failure::AfterAdvance)
            throw identity_registry::Refused();
    }
};

Proposal proposal(unsigned role, const Digest& authority_id,
                  const Digest& supervisor_session,
                  const Selection& selected,
                  Digest party_session = {}) {
    if (party_session == Digest{}) party_session = id(0x80 + role);
    return Proposal::test_only_mint(
        role, authority_id, supervisor_session, party_session,
        AttemptLineageCommitment::test_only_mint(
            selected.run, selected.trial, selected.attempt, selected.cohort),
        DirectAcceptedHeadCommitment::test_only_mint(selected.accepted_head),
        CanonicalOwnerContractsCommitment::test_only_mint(
            selected.owner_contracts));
}

std::shared_ptr<MemoryAnchor> memory_anchor(
    identity_registry::Registry& registry,
    MemoryAnchor::Failure failure = MemoryAnchor::Failure::None) {
    return std::make_shared<MemoryAnchor>(registry.snapshot(), failure);
}

SupervisorAnchorPolicy anchor_policy(
    std::shared_ptr<ExternalMonotonicAnchor> external,
    unsigned value = 0x60) {
    return SupervisorAnchorPolicy::test_only_mint(PublicAnchorPolicy{
        .policy_identity = id(value),
        .permission_separated = true,
        .monotonic = true,
        .child_path_exposed = false,
        .child_fd_exposed = false,
    }, std::move(external));
}

SupervisorAnchorPolicy anchor_policy(
    identity_registry::Registry& registry, unsigned value = 0x60) {
    return anchor_policy(memory_anchor(registry), value);
}

DurableLockCommitment durable_lock(unsigned role, const Selection& selected,
                                   Digest lock_identity) {
    return DurableLockCommitment::test_only_mint(
        role, identity_registry::selection_identity(selected),
        selected.accepted_head, lock_identity);
}

DirectAcceptedHeadCommitment direct_head(Digest identity) {
    return DirectAcceptedHeadCommitment::test_only_mint(identity);
}

template<class T>
concept HasJournalPath = requires(const T& value) { value.journal_path; };
template<class T>
concept HasAnchorPath = requires(const T& value) { value.anchor_path; };
template<class T>
concept HasRegistryFd = requires(const T& value) { value.registry_fd; };

template<class Callable>
void expect_refusal(Callable&& callable) {
    bool refused = false;
    try { callable(); } catch (const identity_registry::Refused&) { refused = true; }
    assert(refused);
}

void submit_all(Supervisor& supervisor, const Digest& authority_id,
                const Digest& session, const Selection& selected) {
    for (unsigned role = 0; role < 3; ++role)
        supervisor.submit(proposal(role, authority_id, session, selected));
}

void activate_batch(ApprovalBatch& batch, const Digest& authority_id,
                    const Digest& session, const Selection& selected) {
    assert(!batch.activated());
    for (unsigned role = 0; role < 3; ++role) {
        const auto expected = proposal(role, authority_id, session, selected);
        const auto preview = batch.preview(role, expected.party_session());
        assert(preview.role == role);
        assert(preview.selection_identity ==
               identity_registry::selection_identity(selected));
        batch.acknowledge(role, expected.party_session(),
                          preview.approval_identity);
    }
    assert(batch.activated());
}

std::vector<unsigned char> read_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

void write_file(const std::filesystem::path& path,
                const std::vector<unsigned char>& bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    output.close();
    assert(output.good());
    assert(::chmod(path.c_str(), 0600) == 0);
}

void happy_two_phase() {
    static_assert(!std::copy_constructible<PartyApproval>);
    static_assert(!std::copy_constructible<RegisteredFreshAttempt>);
    static_assert(!std::copy_constructible<OwnerIntakePermit>);
    static_assert(!std::default_initializable<RegisteredFreshAttempt>);

    Root root;
    const auto auth = authority();
    auto registry = identity_registry::Registry::initialize_fresh_unfunded(
        root.journal, root.anchor, auth);
    const auto authority_id = registry.snapshot().authority_identity;
    const auto session = id(0x70);
    const auto selected = selection();
    Supervisor supervisor(registry, session, anchor_policy(registry));
    assert(!supervisor.ready());
    supervisor.submit(proposal(2, authority_id, session, selected));
    supervisor.submit(proposal(0, authority_id, session, selected));
    assert(!supervisor.ready());
    supervisor.submit(proposal(1, authority_id, session, selected));
    assert(supervisor.ready());
    auto approvals = supervisor.approve();
    assert(registry.snapshot().sequence == 1);
    activate_batch(approvals, authority_id, session, selected);

    for (unsigned role = 0; role < 3; ++role) {
        const auto expected = proposal(role, authority_id, session, selected);
        auto approval = approvals.take(role, expected.party_session());
        assert(approval.public_receipt().role == role);
        assert(approval.public_receipt().selection_identity ==
               identity_registry::selection_identity(selected));
        auto attempt = approval.recheck_before_lock(
            expected, direct_head(selected.accepted_head));
        assert(attempt.public_receipt().accepted_head == selected.accepted_head);
        auto permit = attempt.burn_immediately_before_owner_intake(
            role, direct_head(selected.accepted_head),
            durable_lock(role, selected, id(0x900 + role)));
        const auto receipt = permit.consume_for_claim(role);
        assert(receipt.role == role);
        assert(receipt.durable_lock == id(0x900 + role));
    }
}

void disagreement_partial_and_abort_refuse() {
    const auto auth = authority();
    {
        Root root;
        auto registry = identity_registry::Registry::initialize_fresh_unfunded(
            root.journal, root.anchor, auth);
        const auto authority_id = registry.snapshot().authority_identity;
        const auto session = id(0x200);
        Supervisor supervisor(registry, session, anchor_policy(registry));
        supervisor.submit(proposal(0, authority_id, session, selection()));
        supervisor.submit(proposal(1, authority_id, session, selection()));
        assert(!supervisor.ready());
        expect_refusal([&] { (void)supervisor.approve(); });
        assert(registry.snapshot().sequence == 0);
    }

    for (unsigned mutation = 0; mutation < 8; ++mutation) {
        Root root;
        auto registry = identity_registry::Registry::initialize_fresh_unfunded(
            root.journal, root.anchor, auth);
        const auto authority_id = registry.snapshot().authority_identity;
        const auto session = id(0x240 + mutation);
        Supervisor supervisor(registry, session, anchor_policy(registry));
        const auto common = selection(0x300 + mutation * 0x20);
        supervisor.submit(proposal(0, authority_id, session, common));
        supervisor.submit(proposal(1, authority_id, session, common));
        auto changed = common;
        if (mutation == 0) changed.run = id(0x500 + mutation);
        if (mutation == 1) changed.trial = id(0x500 + mutation);
        if (mutation == 2) changed.attempt = id(0x500 + mutation);
        if (mutation == 3) changed.cohort = id(0x500 + mutation);
        if (mutation == 4) changed.accepted_head = id(0x500 + mutation);
        if (mutation >= 5) changed.owner_contracts[mutation - 5] = id(0x500 + mutation);
        expect_refusal([&] {
            supervisor.submit(proposal(2, authority_id, session, changed));
        });
        assert(registry.snapshot().sequence == 0);
    }

    for (unsigned mutation = 0; mutation < 4; ++mutation) {
        Root root;
        auto registry = identity_registry::Registry::initialize_fresh_unfunded(
            root.journal, root.anchor, auth);
        const auto authority_id = registry.snapshot().authority_identity;
        const auto session = id(0x600 + mutation);
        Supervisor supervisor(registry, session, anchor_policy(registry));
        auto first = proposal(0, authority_id, session,
                              selection(0x700 + mutation * 0x20));
        supervisor.submit(first);
        auto bad_authority = authority_id;
        auto bad_session = session;
        auto bad_party = id(0x81);
        unsigned bad_role = 1;
        if (mutation == 0) bad_authority = id(0x800);
        if (mutation == 1) bad_session = id(0x801);
        if (mutation == 2) bad_party = first.party_session();
        if (mutation == 3) bad_role = 0;
        auto bad = proposal(bad_role, bad_authority, bad_session,
                            first.public_selection_hashes(), bad_party);
        expect_refusal([&] { supervisor.submit(bad); });
        assert(registry.snapshot().sequence == 0);
    }

    {
        Root root;
        auto registry = identity_registry::Registry::initialize_fresh_unfunded(
            root.journal, root.anchor, auth);
        const auto authority_id = registry.snapshot().authority_identity;
        const auto session = id(0x880);
        Supervisor supervisor(registry, session, anchor_policy(registry));
        const auto identical = proposal(0, authority_id, session, selection(0x890));
        supervisor.submit(identical);
        expect_refusal([&] { supervisor.submit(identical); });
        assert(registry.snapshot().sequence == 0);
    }

    {
        Root root;
        auto registry = identity_registry::Registry::initialize_fresh_unfunded(
            root.journal, root.anchor, auth);
        const auto authority_id = registry.snapshot().authority_identity;
        const auto session = id(0x900);
        auto aborted = selection(0x910);
        aborted.run = identity_registry::mandatory_aborted_run();
        Supervisor supervisor(registry, session, anchor_policy(registry));
        submit_all(supervisor, authority_id, session, aborted);
        expect_refusal([&] { (void)supervisor.approve(); });
        assert(registry.snapshot().sequence == 0);
    }
}

template<class Callable>
void with_batch(unsigned base, Callable&& callable) {
    Root root;
    const auto auth = authority();
    auto registry = identity_registry::Registry::initialize_fresh_unfunded(
        root.journal, root.anchor, auth);
    const auto authority_id = registry.snapshot().authority_identity;
    const auto session = id(base + 0x10);
    const auto selected = selection(base + 0x20);
    Supervisor supervisor(registry, session, anchor_policy(registry));
    submit_all(supervisor, authority_id, session, selected);
    auto batch = supervisor.approve();
    activate_batch(batch, authority_id, session, selected);
    callable(batch, authority_id, session, selected);
}

void stale_wrong_role_and_replay_refuse() {
    with_batch(0xa00, [](auto& batch, const auto& authority_id,
                         const auto& session, const auto& selected) {
        expect_refusal([&] { (void)batch.take(0, id(0xdead)); });
        expect_refusal([&] {
            (void)batch.take(
                1, proposal(1, authority_id, session, selected).party_session());
        });
    });

    with_batch(0xb00, [](auto& batch, const auto& authority_id,
                         const auto& session, const auto& selected) {
        const auto expected = proposal(0, authority_id, session, selected);
        auto approval = batch.take(0, expected.party_session());
        expect_refusal([&] {
            (void)approval.recheck_before_lock(expected, direct_head(id(0xbeef)));
        });
        expect_refusal([&] {
            (void)approval.recheck_before_lock(
                expected, direct_head(selected.accepted_head));
        });
    });

    with_batch(0xc00, [](auto& batch, const auto& authority_id,
                         const auto& session, const auto& selected) {
        const auto expected = proposal(1, authority_id, session, selected);
        auto approval = batch.take(1, expected.party_session());
        auto attempt = approval.recheck_before_lock(
            expected, direct_head(selected.accepted_head));
        expect_refusal([&] {
            (void)attempt.burn_immediately_before_owner_intake(
                2, direct_head(selected.accepted_head),
                durable_lock(2, selected, id(0xcafe)));
        });
        expect_refusal([&] {
            (void)attempt.burn_immediately_before_owner_intake(
                1, direct_head(selected.accepted_head),
                durable_lock(1, selected, id(0xcafe)));
        });
    });

    with_batch(0xd00, [](auto& batch, const auto& authority_id,
                         const auto& session, const auto& selected) {
        const auto expected = proposal(2, authority_id, session, selected);
        auto approval = batch.take(2, expected.party_session());
        auto attempt = approval.recheck_before_lock(
            expected, direct_head(selected.accepted_head));
        auto permit = attempt.burn_immediately_before_owner_intake(
            2, direct_head(selected.accepted_head),
            durable_lock(2, selected, id(0xdafe)));
        expect_refusal([&] { (void)permit.consume_for_claim(1); });
        expect_refusal([&] { (void)permit.consume_for_claim(2); });
    });
}

void linear_moves_second_head_and_zero_lock_refuse() {
    with_batch(0xd40, [](auto& batch, const auto& authority_id,
                         const auto& session, const auto& selected) {
        const auto expected = proposal(0, authority_id, session, selected);
        auto original = batch.take(0, expected.party_session());
        PartyApproval moved(std::move(original));
        expect_refusal([&] {
            (void)original.recheck_before_lock(
                expected, direct_head(selected.accepted_head));
        });
        auto first_attempt = moved.recheck_before_lock(
            expected, direct_head(selected.accepted_head));
        RegisteredFreshAttempt moved_attempt(std::move(first_attempt));
        expect_refusal([&] {
            (void)first_attempt.burn_immediately_before_owner_intake(
                0, direct_head(selected.accepted_head),
                durable_lock(0, selected, id(0xd41)));
        });
        auto permit = moved_attempt.burn_immediately_before_owner_intake(
            0, direct_head(selected.accepted_head),
            durable_lock(0, selected, id(0xd42)));
        OwnerIntakePermit moved_permit(std::move(permit));
        expect_refusal([&] { (void)permit.consume_for_claim(0); });
        (void)moved_permit.consume_for_claim(0);
        expect_refusal([&] { (void)moved_permit.consume_for_claim(0); });
    });

    with_batch(0xd80, [](auto& batch, const auto& authority_id,
                         const auto& session, const auto& selected) {
        const auto expected = proposal(1, authority_id, session, selected);
        auto approval = batch.take(1, expected.party_session());
        auto attempt = approval.recheck_before_lock(
            expected, direct_head(selected.accepted_head));
        expect_refusal([&] {
            (void)attempt.burn_immediately_before_owner_intake(
                1, direct_head(id(0xd81)),
                durable_lock(1, selected, id(0xd82)));
        });
        expect_refusal([&] {
            (void)attempt.burn_immediately_before_owner_intake(
                1, direct_head(selected.accepted_head),
                durable_lock(1, selected, id(0xd82)));
        });
    });

    with_batch(0xdc0, [](auto& batch, const auto& authority_id,
                         const auto& session, const auto& selected) {
        const auto expected = proposal(2, authority_id, session, selected);
        auto approval = batch.take(2, expected.party_session());
        auto attempt = approval.recheck_before_lock(
            expected, direct_head(selected.accepted_head));
        expect_refusal([&] {
            (void)attempt.burn_immediately_before_owner_intake(
                2, direct_head(selected.accepted_head),
                durable_lock(2, selected, Digest{}));
        });
    });
}

void concurrent_parent_race() {
    Root root;
    const auto auth = authority();
    auto registry = identity_registry::Registry::initialize_fresh_unfunded(
        root.journal, root.anchor, auth);
    const auto authority_id = registry.snapshot().authority_identity;
    const auto selected = selection(0xe00);
    Supervisor first(registry, id(0xe20), anchor_policy(registry, 0xe30));
    Supervisor second(registry, id(0xe21), anchor_policy(registry, 0xe30));
    submit_all(first, authority_id, id(0xe20), selected);
    submit_all(second, authority_id, id(0xe21), selected);
    std::atomic<unsigned> succeeded{0}, refused{0};
    const auto run = [&](Supervisor& supervisor) {
        try { (void)supervisor.approve(); ++succeeded; }
        catch (const identity_registry::Refused&) { ++refused; }
    };
    std::thread a(run, std::ref(first));
    std::thread b(run, std::ref(second));
    a.join(); b.join();
    assert(succeeded == 1 && refused == 1);
    assert(registry.snapshot().sequence == 1);
}

void same_object_capability_races() {
    const auto race = [](auto&& callable) {
        std::atomic<unsigned> succeeded{0}, refused{0};
        const auto run = [&] {
            try { callable(); ++succeeded; }
            catch (const identity_registry::Refused&) { ++refused; }
        };
        std::thread first(run), second(run);
        first.join(); second.join();
        assert(succeeded == 1 && refused == 1);
    };

    with_batch(0xe40, [&](auto& batch, const auto& authority_id,
                          const auto& session, const auto& selected) {
        const auto expected = proposal(0, authority_id, session, selected);
        race([&] { (void)batch.take(0, expected.party_session()); });
    });

    with_batch(0xe80, [&](auto& batch, const auto& authority_id,
                          const auto& session, const auto& selected) {
        const auto expected = proposal(1, authority_id, session, selected);
        auto approval = batch.take(1, expected.party_session());
        race([&] {
            (void)approval.recheck_before_lock(
                expected, direct_head(selected.accepted_head));
        });
    });

    with_batch(0xec0, [&](auto& batch, const auto& authority_id,
                          const auto& session, const auto& selected) {
        const auto expected = proposal(2, authority_id, session, selected);
        auto approval = batch.take(2, expected.party_session());
        auto attempt = approval.recheck_before_lock(
            expected, direct_head(selected.accepted_head));
        race([&] {
            (void)attempt.burn_immediately_before_owner_intake(
                2, direct_head(selected.accepted_head),
                durable_lock(2, selected, id(0xeee)));
        });
    });

    with_batch(0xf00, [&](auto& batch, const auto& authority_id,
                          const auto& session, const auto& selected) {
        const auto expected = proposal(0, authority_id, session, selected);
        auto approval = batch.take(0, expected.party_session());
        auto attempt = approval.recheck_before_lock(
            expected, direct_head(selected.accepted_head));
        auto permit = attempt.burn_immediately_before_owner_intake(
            0, direct_head(selected.accepted_head),
            durable_lock(0, selected, id(0xf11)));
        race([&] { (void)permit.consume_for_claim(0); });
    });
}

void approval_activation_barrier_refuses_bad_ack() {
    const auto run = [](bool duplicate) {
        Root root;
        const auto auth = authority();
        auto registry = identity_registry::Registry::initialize_fresh_unfunded(
            root.journal, root.anchor, auth);
        const auto authority_id = registry.snapshot().authority_identity;
        const auto session = id(duplicate ? 0x1510 : 0x1520);
        const auto selected = selection(duplicate ? 0x1530 : 0x1550);
        Supervisor supervisor(registry, session, anchor_policy(registry));
        submit_all(supervisor, authority_id, session, selected);
        auto batch = supervisor.approve();
        const auto expected = proposal(0, authority_id, session, selected);
        const auto preview = batch.preview(0, expected.party_session());
        if (duplicate) {
            batch.acknowledge(0, expected.party_session(),
                              preview.approval_identity);
            expect_refusal([&] {
                batch.acknowledge(0, expected.party_session(),
                                  preview.approval_identity);
            });
        } else {
            expect_refusal([&] {
                batch.acknowledge(0, expected.party_session(), id(0xdead));
            });
        }
        assert(!batch.activated());
        expect_refusal([&] {
            (void)batch.take(0, expected.party_session());
        });
        assert(registry.snapshot().sequence == 1);
    };
    run(false);
    run(true);
}

void external_anchor_gate_and_crash_boundaries() {
    const auto auth = authority();
    {
        Root root;
        auto registry = identity_registry::Registry::initialize_fresh_unfunded(
            root.journal, root.anchor, auth);
        auto external = memory_anchor(registry);
        const auto authority_id = registry.snapshot().authority_identity;
        const auto selected = selection(0x1600);
        Supervisor supervisor(registry, id(0x1610), anchor_policy(external));
        submit_all(supervisor, authority_id, id(0x1610), selected);
        (void)supervisor.approve();
        const auto local = registry.snapshot();
        const ExternalAnchorSnapshot expected{
            local.authority_identity, local.sequence, local.checkpoint};
        assert(external->snapshot() == expected);
    }

    {
        Root root;
        auto registry = identity_registry::Registry::initialize_fresh_unfunded(
            root.journal, root.anchor, auth);
        auto state = registry.snapshot();
        auto wrong = std::make_shared<MemoryAnchor>(ExternalAnchorSnapshot{
            state.authority_identity, state.sequence + 1, id(0x1620)});
        Supervisor supervisor(registry, id(0x1621), anchor_policy(wrong));
        submit_all(supervisor, state.authority_identity, id(0x1621),
                   selection(0x1640));
        expect_refusal([&] { (void)supervisor.approve(); });
        assert(registry.snapshot().sequence == 0);
    }

    for (const auto failure : {MemoryAnchor::Failure::BeforeAdvance,
                               MemoryAnchor::Failure::AfterAdvance}) {
        Root root;
        auto registry = identity_registry::Registry::initialize_fresh_unfunded(
            root.journal, root.anchor, auth);
        auto external = memory_anchor(registry, failure);
        const auto authority_id = registry.snapshot().authority_identity;
        const auto selected = selection(
            0x1680 + static_cast<unsigned>(failure) * 0x20);
        Supervisor supervisor(registry,
            id(0x16c0 + static_cast<unsigned>(failure)),
            anchor_policy(external));
        submit_all(supervisor, authority_id,
            id(0x16c0 + static_cast<unsigned>(failure)), selected);
        expect_refusal([&] { (void)supervisor.approve(); });
        const auto local = registry.snapshot();
        assert(local.sequence == 1);
        if (failure == MemoryAnchor::Failure::BeforeAdvance)
            assert(external->snapshot().sequence == 0);
        else
            assert(external->snapshot().sequence == 1);
    }

    {
        Root root;
        auto registry = identity_registry::Registry::initialize_fresh_unfunded(
            root.journal, root.anchor, auth);
        auto external = memory_anchor(registry);
        const auto authority_id = registry.snapshot().authority_identity;
        const auto selected = selection(0x1700);
        Supervisor supervisor(registry, id(0x1710), anchor_policy(external));
        submit_all(supervisor, authority_id, id(0x1710), selected);
        expect_refusal([&] {
            (void)supervisor.approve({}, [&](Supervisor::Boundary boundary) {
                assert(boundary == Supervisor::Boundary::ExternalAnchorAdvanced);
                throw std::runtime_error("after external anchor advance");
            });
        });
        assert(registry.snapshot().sequence == 1);
        assert(external->snapshot().sequence == 1);
        Supervisor retry(registry, id(0x1720), anchor_policy(external));
        submit_all(retry, authority_id, id(0x1720), selected);
        expect_refusal([&] { (void)retry.approve(); });
    }
}

void crash_and_partial_approval_burn_identity() {
    const auto auth = authority();
    for (const auto boundary : {
             identity_registry::WriteBoundary::JournalWritten,
             identity_registry::WriteBoundary::JournalSynced,
             identity_registry::WriteBoundary::AnchorWritten,
             identity_registry::WriteBoundary::AnchorSynced}) {
        Root root;
        const auto session = id(0xf00 + static_cast<unsigned>(boundary));
        const auto selected = selection(0xf20 + static_cast<unsigned>(boundary) * 0x20);
        {
            auto registry = identity_registry::Registry::initialize_fresh_unfunded(
                root.journal, root.anchor, auth);
            const auto authority_id = registry.snapshot().authority_identity;
            Supervisor supervisor(registry, session, anchor_policy(registry));
            submit_all(supervisor, authority_id, session, selected);
            expect_refusal([&] {
                (void)supervisor.approve([&](auto at) {
                    if (at == boundary) throw std::runtime_error("injected crash");
                });
            });
        }
        if (boundary == identity_registry::WriteBoundary::JournalWritten ||
            boundary == identity_registry::WriteBoundary::JournalSynced) {
            expect_refusal([&] {
                (void)identity_registry::Registry::open_existing(
                    root.journal, root.anchor, auth);
            });
        } else {
            auto registry = identity_registry::Registry::open_existing(
                root.journal, root.anchor, auth);
            assert(registry.snapshot().sequence == 1);
            const auto authority_id = registry.snapshot().authority_identity;
            Supervisor retry(registry,
                             id(0xff0 + static_cast<unsigned>(boundary)),
                             anchor_policy(registry));
            submit_all(retry, authority_id,
                       id(0xff0 + static_cast<unsigned>(boundary)), selected);
            expect_refusal([&] { (void)retry.approve(); });
        }
    }

    Root root;
    auto registry = identity_registry::Registry::initialize_fresh_unfunded(
        root.journal, root.anchor, auth);
    const auto authority_id = registry.snapshot().authority_identity;
    const auto selected = selection(0x1200);
    {
        Supervisor supervisor(registry, id(0x1210), anchor_policy(registry));
        submit_all(supervisor, authority_id, id(0x1210), selected);
        auto batch = supervisor.approve();
        const auto expected = proposal(
            0, authority_id, id(0x1210), selected);
        const auto preview = batch.preview(0, expected.party_session());
        batch.acknowledge(0, expected.party_session(),
                          preview.approval_identity);
        assert(!batch.activated());
        expect_refusal([&] {
            (void)batch.take(0, expected.party_session());
        });
    }
    Supervisor retry(registry, id(0x1220), anchor_policy(registry));
    submit_all(retry, authority_id, id(0x1220), selected);
    expect_refusal([&] { (void)retry.approve(); });
}

void rollback_and_source_boundary() {
    static_assert(!std::default_initializable<Proposal>);
    static_assert(!std::default_initializable<AttemptLineageCommitment>);
    static_assert(!std::default_initializable<DirectAcceptedHeadCommitment>);
    static_assert(!std::default_initializable<CanonicalOwnerContractsCommitment>);
    static_assert(!std::default_initializable<DurableLockCommitment>);
    static_assert(!HasJournalPath<Proposal>);
    static_assert(!HasAnchorPath<Proposal>);
    static_assert(!HasRegistryFd<Proposal>);
    static_assert(!HasJournalPath<PublicApproval>);
    static_assert(!HasAnchorPath<PublicApproval>);
    static_assert(!HasRegistryFd<PublicApproval>);
    static_assert(!HasJournalPath<PublicFreshAttempt>);
    static_assert(!HasRegistryFd<PublicFreshAttempt>);
    static_assert(!HasJournalPath<PublicIntakePermit>);
    static_assert(!HasRegistryFd<PublicIntakePermit>);
    Root root;
    const auto auth = authority();
    const auto old_anchor = [&] {
        auto registry = identity_registry::Registry::initialize_fresh_unfunded(
            root.journal, root.anchor, auth);
        const auto bytes = read_file(root.anchor / "latest.bin");
        const auto authority_id = registry.snapshot().authority_identity;
        Supervisor supervisor(registry, id(0x1300), anchor_policy(registry));
        submit_all(supervisor, authority_id, id(0x1300), selection(0x1320));
        (void)supervisor.approve();
        return bytes;
    }();
    write_file(root.anchor / "latest.bin", old_anchor);
    expect_refusal([&] {
        (void)identity_registry::Registry::open_existing(
            root.journal, root.anchor, auth);
    });

    const auto status = source_status();
    assert(status.schema == "kpb-registered-attempt-supervisor-source-only/v1");
    assert(status.status == "UNQUALIFIED_SOURCE_ONLY");
    assert(status.registry_mounted_to_children == false);
    assert(status.supervisor_anchor_path_or_fd_exposed_to_children == false);
    assert(status.permission_separated_monotonic_anchor_backend == false);
    assert(status.external_monotonic_anchor_interface == true);
    assert(status.coordinated_same_inode_rollback_detected == false);
    assert(status.actual_process_ipc_integration == false);
    assert(status.typed_registered_bridge_integration == false);
    assert(status.direct_accepted_head_type_integration == false);
    assert(status.canonical_owner_contract_type_integration == false);
    assert(status.claim_owner_intake_integration == false);
    assert(status.registered_driver_configured == false);
    assert(status.launch_authorized == false);

    for (unsigned mutation = 0; mutation < 5; ++mutation) {
        Root policy_root;
        auto registry = identity_registry::Registry::initialize_fresh_unfunded(
            policy_root.journal, policy_root.anchor, auth);
        PublicAnchorPolicy invalid{
            .policy_identity = id(0x1400 + mutation),
            .permission_separated = true,
            .monotonic = true,
            .child_path_exposed = false,
            .child_fd_exposed = false,
        };
        if (mutation == 0) invalid.policy_identity = {};
        if (mutation == 1) invalid.permission_separated = false;
        if (mutation == 2) invalid.monotonic = false;
        if (mutation == 3) invalid.child_path_exposed = true;
        if (mutation == 4) invalid.child_fd_exposed = true;
        auto policy = SupervisorAnchorPolicy::test_only_mint(
            invalid, memory_anchor(registry));
        expect_refusal([&] {
            Supervisor supervisor(registry, id(0x1450 + mutation),
                                  std::move(policy));
        });
        assert(registry.snapshot().sequence == 0);
    }
}
} // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    const std::string control(argv[1]);
    if (control == "happy-two-phase") happy_two_phase();
    else if (control == "disagreement-partial-abort") disagreement_partial_and_abort_refuse();
    else if (control == "stale-wrong-role-replay") stale_wrong_role_and_replay_refuse();
    else if (control == "linear-move-second-head-zero-lock") linear_moves_second_head_and_zero_lock_refuse();
    else if (control == "concurrent-parent-race") concurrent_parent_race();
    else if (control == "same-object-capability-races") same_object_capability_races();
    else if (control == "approval-activation-barrier") approval_activation_barrier_refuses_bad_ack();
    else if (control == "external-anchor-gate") external_anchor_gate_and_crash_boundaries();
    else if (control == "crash-partial-approval") crash_and_partial_approval_burn_identity();
    else if (control == "rollback-source-boundary") rollback_and_source_boundary();
    else assert(false);
}
