#include "../authenticated_baseline_owner_receiver.hpp"

#include <array>
#include <atomic>
#include <cassert>
#include <concepts>
#include <string>
#include <thread>

using namespace kpi::mpc::financial::registered_driver;
using namespace kpi::mpc::financial::registered_driver::baseline_disclosure;

namespace {
Digest id(unsigned long long value) {
    Digest result{};
    for (unsigned i = 0; i < 8; ++i)
        result[i] = static_cast<unsigned char>(value >> (8 * i));
    return result;
}

template<class Callable> void refused(Callable&& callable) {
    bool failed = false;
    try { callable(); }
    catch (const kpi::mpc::financial::identity_registry::Refused&) {
        failed = true;
    }
    assert(failed);
}

PrivatePartyBaselineOwnerEffects value(unsigned round, unsigned role) {
    PrivatePartyBaselineOwnerEffects result{
        .classification =
            CaptureClassification::ExplicitOwnerPublicEffectsBaseline,
        .round = round,
        .role = role,
        .run = id(0x10 + round),
        .trial = id(0x11),
        .attempt = id(0x20 + round),
        .cohort = id(0x30 + round),
        .capture_plan_identity = id(0x40 + round),
        .projection_identity = id(0x50 + round),
        .context_identity = id(0x60 + round),
        .relation_source_identity = id(0x70),
        .owner_effects_recipe_identity = id(0x71),
        .baseline_plan_identity = id(0x80 + 3 * round + role),
        .verified_egress_identity = id(0x90 + 3 * round + role),
        .policy_identity = id(0xa0),
        .roster_authority_identity = id(0xa1),
        .roster_root_identity = id(0xa2),
        .consent_nonce = id(0xb0 + round),
    };
    for (unsigned owner = 0; owner < 3; ++owner) {
        result.owner_contracts[owner] = id(0x100 + 8 * round + owner);
        result.logical_owner_identities[owner] = id(0x180 + owner);
        result.pre_disclosure_challenge_identities[owner] =
            id(0x1c0 + 8 * round + owner);
        result.owner_sessions[owner] = id(
            0x200 + 32 * round + 4 * role + owner);
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
        truth.logical_owner_identity =
            result.logical_owner_identities[owner];
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

PartyBaselineOwnerEffectsAuthority party(unsigned round, unsigned role) {
    return PartyBaselineOwnerEffectsAuthority::test_only_mint(
        value(round, role));
}

PublicAuthorizedAttempt attempt_for(const PrivatePartyBaselineOwnerEffects& value) {
    PublicAuthorizedAttempt result{};
    result.role = value.role;
    result.round = value.round;
    result.classification = value.classification;
    result.run = value.run;
    result.trial = value.trial;
    result.attempt = value.attempt;
    result.cohort = value.cohort;
    result.durable_lock = id(0xd0 + value.round);
    result.owner_contracts = value.owner_contracts;
    result.capture_plan_identity = value.capture_plan_identity;
    return result;
}

BaselineOwnerScoringLaunchAuthority complete() {
    BaselineOwnerScoringParentCollector parent;
    for (unsigned round = 1; round <= 2; ++round)
        for (unsigned role = 0; role < 3; ++role)
            parent.submit(party(round, role));
    return parent.finish();
}

void happy() {
    auto launch = complete();
    for (unsigned owner = 0; owner < 3; ++owner) {
        auto input = launch.take_owner(owner);
        const auto& rounds = input.test_only_rounds();
        assert(rounds[0].owner == owner && rounds[0].round == 1 &&
               rounds[1].owner == owner && rounds[1].round == 2 &&
               rounds[0].run == id(0x11) &&
               rounds[1].run == id(0x12) &&
               rounds[0].run != rounds[1].run &&
               rounds[0].public_nullifier == id(0x308 + owner) &&
               rounds[1].public_tuple_hashes[1] ==
                   id(0x421 + 2 * owner));
    }
    refused([&] { (void)launch.take_owner(0); });
}

void mutations() {
    for (unsigned mutation = 0; mutation < 14; ++mutation) {
        BaselineOwnerScoringParentCollector parent;
        bool rejected = false;
        for (unsigned round = 1; round <= 2 && !rejected; ++round) {
            for (unsigned role = 0; role < 3 && !rejected; ++role) {
                auto changed = value(round, role);
                if (round == 1 && role == 1) {
                    if (mutation == 0) changed.role = 0;
                    if (mutation == 1) changed.round = 2;
                    if (mutation == 2)
                        changed.owner_truth[0].public_nullifier = id(0xdead);
                    if (mutation == 3) changed.consent_nonce = id(0xbeef);
                    if (mutation == 4)
                        changed.owner_sessions[1] =
                            value(1, 0).owner_sessions[1];
                    if (mutation == 5)
                        changed.projection_identity = id(0xcafe);
                    if (mutation == 6)
                        changed.owner_contracts[2] = id(0xfade);
                    if (mutation == 7)
                        changed.classification =
                            CaptureClassification::HiddenCandidate;
                    if (mutation == 8)
                        changed.logical_owner_identities[1] = id(0xf001);
                    if (mutation == 9)
                        changed.owner_truth[1].logical_owner_identity =
                            id(0xf002);
                    if (mutation == 10) changed.trial = id(0xf003);
                    if (mutation == 11)
                        changed.roster_authority_identity = id(0xf004);
                    if (mutation == 12)
                        changed.pre_disclosure_challenge_identities[0] =
                            id(0xf005);
                    if (mutation == 13)
                        changed.owner_truth[0]
                            .pre_disclosure_challenge_identity = id(0xf006);
                }
                try {
                    parent.submit(
                        PartyBaselineOwnerEffectsAuthority::test_only_mint(
                            std::move(changed)));
                } catch (const kpi::mpc::financial::identity_registry::Refused&) {
                    rejected = true;
                }
            }
        }
        if (!rejected) refused([&] { (void)parent.finish(); });
    }

    BaselineOwnerScoringParentCollector replay;
    auto once = party(1, 0);
    replay.submit(std::move(once));
    refused([&] { replay.submit(std::move(once)); });
    refused([&] { (void)replay.finish(); });

    BaselineOwnerScoringParentCollector swapped_roster;
    for (unsigned round = 1; round <= 2; ++round)
        for (unsigned role = 0; role < 3; ++role) {
            auto changed = value(round, role);
            if (round == 2) {
                std::swap(changed.logical_owner_identities[0],
                          changed.logical_owner_identities[1]);
                changed.owner_truth[0].logical_owner_identity =
                    changed.logical_owner_identities[0];
                changed.owner_truth[1].logical_owner_identity =
                    changed.logical_owner_identities[1];
            }
            swapped_roster.submit(
                PartyBaselineOwnerEffectsAuthority::test_only_mint(
                    std::move(changed)));
        }
    refused([&] { (void)swapped_roster.finish(); });

    // Cross-round scope is checked only after both complete three-party
    // copies exist. A reused financial run or a changed trial/roster/policy
    // must therefore poison the final join even when all three roles agree.
    for (unsigned mutation = 0; mutation < 4; ++mutation) {
        BaselineOwnerScoringParentCollector cross_round;
        for (unsigned round = 1; round <= 2; ++round)
            for (unsigned role = 0; role < 3; ++role) {
                auto changed = value(round, role);
                if (round == 2 && mutation == 0) {
                    changed.run = id(0x11);
                    for (auto& truth : changed.owner_truth)
                        truth.run = changed.run;
                }
                if (round == 2 && mutation == 1) {
                    changed.trial = id(0xf101);
                    for (auto& truth : changed.owner_truth)
                        truth.trial = changed.trial;
                }
                if (round == 2 && mutation == 2) {
                    changed.roster_authority_identity = id(0xf102);
                    for (auto& truth : changed.owner_truth)
                        truth.roster_authority_identity =
                            changed.roster_authority_identity;
                }
                if (round == 2 && mutation == 3)
                    changed.policy_identity = id(0xf103);
                cross_round.submit(
                    PartyBaselineOwnerEffectsAuthority::test_only_mint(
                        std::move(changed)));
            }
        refused([&] { (void)cross_round.finish(); });
    }
}

void race() {
    auto once = party(1, 0);
    std::atomic<unsigned> ready{}, accepted{}, rejected{};
    const auto run = [&] {
        BaselineOwnerScoringParentCollector parent;
        ready.fetch_add(1);
        while (ready.load() != 2) std::this_thread::yield();
        try {
            parent.submit(std::move(once));
            accepted.fetch_add(1);
        } catch (const kpi::mpc::financial::identity_registry::Refused&) {
            rejected.fetch_add(1);
        }
    };
    std::thread first(run), second(run);
    first.join(); second.join();
    assert(accepted.load() == 1 && rejected.load() == 1);

    auto launch = complete();
    ready.store(0); accepted.store(0); rejected.store(0);
    const auto take = [&] {
        ready.fetch_add(1);
        while (ready.load() != 2) std::this_thread::yield();
        try {
            (void)launch.take_owner(1);
            accepted.fetch_add(1);
        } catch (const kpi::mpc::financial::identity_registry::Refused&) {
            rejected.fetch_add(1);
        }
    };
    std::thread take_first(take), take_second(take);
    take_first.join(); take_second.join();
    assert(accepted.load() == 1 && rejected.load() == 1);
    (void)launch.take_owner(0);
    (void)launch.take_owner(2);
    refused([&] { (void)launch.take_owner(1); });
}

void hidden() {
    auto changed = value(1, 0);
    changed.classification = CaptureClassification::HiddenCandidate;
    refused([&] {
        (void)PartyBaselineOwnerEffectsAuthority::test_only_mint(changed);
    });
    const auto status = authenticated_baseline_owner_receiver_source_status();
    assert(status.mutual_tls_owner_reauthentication &&
           status.challenge_ack_bound_to_nonce_and_projection &&
           status.hidden_candidate_receiver_factory_absent &&
           status.owner_truth_routed_only_to_private_scorer &&
           status.observer_capture_export &&
           !status.parent_worker_process_launch_integrated &&
           !status.registered_driver_configured && !status.launch_authorized);
}

void protocol() {
    const auto selected = value(1, 0);
    const auto& truth = selected.owner_truth[1];
    BaselineOwnerPreDisclosureBinding pre{
        .classification = selected.classification,
        .round = selected.round,
        .owner = truth.owner,
        .run = selected.run,
        .trial = selected.trial,
        .attempt = selected.attempt,
        .cohort = selected.cohort,
        .capture_plan_identity = selected.capture_plan_identity,
        .projection_identity = selected.projection_identity,
        .context_identity = selected.context_identity,
        .owner_contract_identity = truth.owner_contract_identity,
        .relation_source_identity = selected.relation_source_identity,
        .owner_effects_recipe_identity =
            selected.owner_effects_recipe_identity,
        .policy_identity = selected.policy_identity,
        .roster_authority_identity = selected.roster_authority_identity,
        .roster_root_identity = selected.roster_root_identity,
    };
    const auto pre_frame =
        BaselineOwnerPreDisclosureProtocol::challenge(pre);
    static_assert(pre_frame.size() == 459);
    const auto parsed = BaselineOwnerPreDisclosureProtocol::parse(pre_frame);
    assert(parsed.owner == pre.owner && parsed.run == pre.run &&
           parsed.trial == pre.trial && parsed.nonce != Digest{});
    auto corrupt_pre = pre_frame;
    corrupt_pre[100] ^= 1;
    refused([&] {
        (void)BaselineOwnerPreDisclosureProtocol::parse(corrupt_pre);
    });
    pre.classification = CaptureClassification::HiddenCandidate;
    refused([&] {
        (void)BaselineOwnerPreDisclosureProtocol::challenge(pre);
    });

    const auto nonce = BaselineOwnerConsentProtocol::consent_nonce(
        selected.classification, truth, selected.relation_source_identity,
        selected.owner_effects_recipe_identity, selected.policy_identity);
    const auto frame = BaselineOwnerConsentProtocol::challenge(
        selected.classification, truth, selected.relation_source_identity,
        selected.owner_effects_recipe_identity, selected.policy_identity,
        truth.pre_disclosure_challenge_identity, nonce);
    const auto ack = BaselineOwnerConsentProtocol::acknowledge(frame);
    static_assert(frame.size() == 683 && ack.size() == 40);
    BaselineOwnerConsentProtocol::require_acknowledgment(frame, ack);

    auto wrong_ack = ack;
    wrong_ack.back() ^= 1;
    refused([&] {
        BaselineOwnerConsentProtocol::require_acknowledgment(
            frame, wrong_ack);
    });
    auto wrong_frame = frame;
    wrong_frame[11] ^= 1;
    refused([&] {
        BaselineOwnerConsentProtocol::require_acknowledgment(
            wrong_frame, ack);
    });
    auto changed_truth = truth;
    changed_truth.projection_identity = id(0xdead);
    const auto changed_nonce = BaselineOwnerConsentProtocol::consent_nonce(
        selected.classification, changed_truth,
        selected.relation_source_identity,
        selected.owner_effects_recipe_identity, selected.policy_identity);
    assert(changed_nonce != nonce);
    refused([&] {
        (void)BaselineOwnerConsentProtocol::challenge(
            CaptureClassification::HiddenCandidate, truth,
            selected.relation_source_identity,
            selected.owner_effects_recipe_identity, selected.policy_identity,
            truth.pre_disclosure_challenge_identity, nonce);
    });
}

void observer_binding() {
    {
        const auto selected = value(1, 0);
        auto source = PartyBaselineOwnerEffectsAuthority::test_only_mint(selected);
        auto attempt = attempt_for(selected);
        auto explicit_effects =
            ExplicitOwnerPublicEffectsAuthority::test_only_from_bound_party(
                source, attempt, attempt.durable_lock,
                selected.projection_identity, selected.context_identity);
        const auto receipt = explicit_effects.consume_for_capture();
        assert(receipt.classification ==
                   CaptureClassification::ExplicitOwnerPublicEffectsBaseline &&
               receipt.round == 1 && receipt.run == selected.run &&
               receipt.trial == selected.trial &&
               receipt.owner_effects[2].public_tuple_hashes ==
                   selected.owner_truth[2].public_tuple_hashes);
        refused([&] {
            (void)ExplicitOwnerPublicEffectsAuthority::
                test_only_from_bound_party(
                    source, attempt, attempt.durable_lock,
                    selected.projection_identity, selected.context_identity);
        });
    }

    for (unsigned mutation = 0; mutation < 13; ++mutation) {
        auto selected = value(1, 0);
        auto attempt = attempt_for(selected);
        auto binding = attempt.durable_lock;
        auto projection = selected.projection_identity;
        auto context = selected.context_identity;
        if (mutation == 0) attempt.classification =
            CaptureClassification::HiddenCandidate;
        if (mutation == 1) attempt.role = 1;
        if (mutation == 2) attempt.round = 2;
        if (mutation == 3) attempt.run = id(0xe3);
        if (mutation == 4) attempt.trial = id(0xe4);
        if (mutation == 5) attempt.attempt = id(0xe5);
        if (mutation == 6) attempt.cohort = id(0xe6);
        if (mutation == 7) attempt.capture_plan_identity = id(0xe7);
        if (mutation == 8) attempt.owner_contracts[1] = id(0xe8);
        if (mutation == 9) binding = id(0xe9);
        if (mutation == 10) projection = id(0xea);
        if (mutation == 11) context = id(0xeb);
        if (mutation == 12) selected.owner_truth[2].public_tuple_hashes[0] =
            selected.owner_truth[2].public_tuple_hashes[1];
        refused([&] {
            auto source =
                PartyBaselineOwnerEffectsAuthority::test_only_mint(selected);
            (void)ExplicitOwnerPublicEffectsAuthority::
                test_only_from_bound_party(
                    source, attempt, binding, projection, context);
        });
    }
}

void surface() {
    static_assert(!std::default_initializable<
                  PartyBaselineOwnerEffectsAuthority>);
    static_assert(!std::constructible_from<
                  PartyBaselineOwnerEffectsAuthority,
                  PrivatePartyBaselineOwnerEffects>);
    static_assert(!std::default_initializable<
                  BaselineOwnerScoringLaunchAuthority>);
    static_assert(!std::copy_constructible<OwnerScoreTruthAuthority>);
}
} // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    const std::string mode(argv[1]);
    if (mode == "happy") happy();
    else if (mode == "mutations") mutations();
    else if (mode == "race") race();
    else if (mode == "hidden") hidden();
    else if (mode == "protocol") protocol();
    else if (mode == "observer") observer_binding();
    else if (mode == "surface") surface();
    else return 2;
}
