#include "../docker_monotonic_anchor_client.hpp"
#include "../registered_attempt_supervisor.hpp"
#include "../registered_identity_registry.hpp"

#include <cassert>
#include <iostream>
#include <memory>
#include <string>

using namespace kpi::mpc::financial;

namespace {
using attempt_supervisor::Digest;

Digest id(unsigned value) {
    Digest result{};
    result[0] = static_cast<unsigned char>(value);
    result[1] = static_cast<unsigned char>(value >> 8);
    result[31] = static_cast<unsigned char>(value ^ 0x3cU);
    return result;
}

identity_registry::Authority authority(char** argv) {
    return identity_registry::Authority{
        .registration = identity_registry::unhex(argv[4]),
        .service = identity_registry::unhex(argv[5]),
        .source = identity_registry::unhex(argv[6]),
        .build = identity_registry::unhex(argv[7]),
        .aborted_runs = {identity_registry::mandatory_aborted_run()},
    };
}

identity_registry::Selection selection() {
    return identity_registry::Selection{
        .run = id(0x100), .trial = id(0x101), .attempt = id(0x102),
        .cohort = id(0x103), .accepted_head = id(0x104),
        .owner_contracts = {id(0x105), id(0x106), id(0x107)},
    };
}

attempt_supervisor::Proposal proposal(
    unsigned role, const Digest& authority_identity,
    const Digest& supervisor_session) {
    const auto selected = selection();
    return attempt_supervisor::Proposal::test_only_mint(
        role, authority_identity, supervisor_session, id(0x200 + role),
        attempt_supervisor::AttemptLineageCommitment::test_only_mint(
            selected.run, selected.trial, selected.attempt, selected.cohort),
        attempt_supervisor::DirectAcceptedHeadCommitment::test_only_mint(
            selected.accepted_head),
        attempt_supervisor::CanonicalOwnerContractsCommitment::test_only_mint(
            selected.owner_contracts));
}

std::string capability_from_stdin() {
    std::string result;
    assert(bool(std::getline(std::cin, result)));
    std::string extra;
    assert(!std::getline(std::cin, extra));
    return result;
}

class ThrowAfterAdvance final
    : public attempt_supervisor::ExternalMonotonicAnchor {
    docker_anchor::Client& inner_;
public:
    explicit ThrowAfterAdvance(docker_anchor::Client& inner) : inner_(inner) {}
    attempt_supervisor::ExternalAnchorSnapshot snapshot() override {
        return inner_.snapshot();
    }
    void compare_and_advance(
        const attempt_supervisor::ExternalAnchorSnapshot& expected,
        const attempt_supervisor::ExternalAnchorSnapshot& next) override {
        inner_.compare_and_advance(expected, next);
        throw identity_registry::Refused();
    }
};

void activate_and_burn(attempt_supervisor::ApprovalBatch& batch,
                       const Digest& authority_identity,
                       const Digest& supervisor_session) {
    const auto selected = selection();
    for (unsigned role = 0; role < 3; ++role) {
        const auto expected = proposal(role, authority_identity, supervisor_session);
        const auto preview = batch.preview(role, expected.party_session());
        batch.acknowledge(role, expected.party_session(),
                          preview.approval_identity);
    }
    assert(batch.activated());
    for (unsigned role = 0; role < 3; ++role) {
        const auto expected = proposal(role, authority_identity, supervisor_session);
        auto approval = batch.take(role, expected.party_session());
        auto fresh = approval.recheck_before_lock(
            expected,
            attempt_supervisor::DirectAcceptedHeadCommitment::test_only_mint(
                selected.accepted_head));
        auto permit = fresh.burn_immediately_before_owner_intake(
            role,
            attempt_supervisor::DirectAcceptedHeadCommitment::test_only_mint(
                selected.accepted_head),
            attempt_supervisor::DurableLockCommitment::test_only_mint(
                role, identity_registry::selection_identity(selected),
                selected.accepted_head, id(0x300 + role)));
        (void)permit.consume_for_claim(role);
    }
}

int initialize(int argc, char** argv) {
    assert(argc == 8);
    auto registry = identity_registry::Registry::initialize_fresh_unfunded(
        argv[2], argv[3], authority(argv));
    const auto state = registry.snapshot();
    std::cout << identity_registry::hex(state.authority_identity) << ' '
              << identity_registry::hex(state.checkpoint) << '\n';
    return 0;
}

int supervise(int argc, char** argv, bool ambiguous) {
    assert(argc == 11);
    auto registry = identity_registry::Registry::open_existing(
        argv[2], argv[3], authority(argv));
    const auto before = registry.snapshot();
    auto capability = docker_anchor::SupervisorCapability::test_only_mint(
        capability_from_stdin());
    auto client = docker_anchor::Client::test_only_connect(
        docker_anchor::PublicConfiguration{
            .socket_path = argv[8],
            .authority_identity = before.authority_identity,
            .configuration_identity = identity_registry::unhex(argv[9]),
            .instance_identity = identity_registry::unhex(argv[10]),
            .service_uid = 65532,
        }, std::move(capability));
    std::unique_ptr<ThrowAfterAdvance> throwing;
    std::shared_ptr<attempt_supervisor::ExternalMonotonicAnchor> anchor;
    if (ambiguous) {
        throwing = std::make_unique<ThrowAfterAdvance>(client);
        anchor = std::shared_ptr<attempt_supervisor::ExternalMonotonicAnchor>(
            throwing.get(), [](attempt_supervisor::ExternalMonotonicAnchor*) {});
    } else {
        anchor = std::shared_ptr<attempt_supervisor::ExternalMonotonicAnchor>(
            &client, [](attempt_supervisor::ExternalMonotonicAnchor*) {});
    }
    auto policy = attempt_supervisor::SupervisorAnchorPolicy::test_only_mint(
        attempt_supervisor::PublicAnchorPolicy{
            .policy_identity = id(0x400),
            .permission_separated = true,
            .monotonic = true,
            .child_path_exposed = false,
            .child_fd_exposed = false,
        }, std::move(anchor));
    const auto session = id(0x500);
    attempt_supervisor::Supervisor supervisor(
        registry, session, std::move(policy));
    for (unsigned role = 0; role < 3; ++role)
        supervisor.submit(proposal(role, before.authority_identity, session));
    assert(supervisor.ready());
    if (ambiguous) {
        bool refused = false;
        try { (void)supervisor.approve(); }
        catch (const identity_registry::Refused&) { refused = true; }
        assert(refused && registry.snapshot().sequence == 1 &&
               client.snapshot().sequence == 1);
    } else {
        auto batch = supervisor.approve();
        activate_and_burn(batch, before.authority_identity, session);
        assert(registry.snapshot().sequence == before.sequence + 1);
    }
    return 0;
}
} // namespace

int main(int argc, char** argv) {
    try {
        assert(argc >= 2);
        const std::string operation(argv[1]);
        if (operation == "initialize") return initialize(argc, argv);
        if (operation == "supervise") return supervise(argc, argv, false);
        if (operation == "ambiguous") return supervise(argc, argv, true);
        return 1;
    } catch (...) {
        return 1;
    }
}
