#include "fresh_owner_arm_isolation.hpp"

#include <cassert>
#include <concepts>
#include <cstdint>
#include <string_view>
#include <utility>

using namespace kpi::mpc::financial;
using namespace kpi::mpc::financial::fresh_owner_issuance;

namespace {

Digest id(std::uint32_t value) {
    Digest result{};
    for (std::size_t index = 0; index < result.size(); ++index)
        result[index] = static_cast<unsigned char>(
            ((value >> ((index % 4) * 8)) & 0xffU) ^
            static_cast<unsigned>(index + 1));
    return result;
}

PrivateArmIsolationTestEvidence arm(
        registered_driver::CaptureClassification classification,
        std::uint32_t base) {
    PrivateArmIsolationTestEvidence result{
        .classification = classification,
        .process_authority_identity = id(base + 1),
        .supervisor_session_identity = id(base + 2),
        .child_pids = {
            static_cast<std::int64_t>(base + 10),
            static_cast<std::int64_t>(base + 11),
            static_cast<std::int64_t>(base + 12),
        },
    };
    for (unsigned owner = 0; owner < 3; ++owner) {
        result.child_sessions[owner] = id(base + 20 + owner);
        result.root_slots[owner] = {
            static_cast<std::uint64_t>(base + 30 + owner),
            static_cast<std::uint64_t>(base + 40 + owner),
        };
        result.logical_owner_ids[owner] = id(base + 50 + owner);
    }
    for (unsigned slot = 0; slot < 6; ++slot) {
        result.contract_ids[slot] = id(base + 100 + slot);
        result.owner_tls_cert_ids[slot] = id(base + 200 + slot);
        result.owner_tls_spki_ids[slot] = id(base + 300 + slot);
        const unsigned round = slot / 3;
        for (unsigned server = 0; server < 3; ++server) {
            result.server_tls_cert_ids[slot][server] =
                id(base + 400 + round * 3 + server);
            result.server_tls_spki_ids[slot][server] =
                id(base + 500 + round * 3 + server);
        }
    }
    return result;
}

template<class Function>
void refuses(Function&& function) {
    bool refused = false;
    try {
        function();
    } catch (const identity_registry::Refused&) {
        refused = true;
    }
    assert(refused);
}

FreshOwnerPrivateArmLaunchAuthority mint(
        PrivateArmIsolationTestEvidence value) {
    return FreshOwnerPrivateArmLaunchAuthority::test_only_mint(
        std::move(value));
}

template<class Mutator>
void cross_arm_refuses(Mutator&& mutator) {
    auto baseline = arm(
        registered_driver::CaptureClassification::
            ExplicitOwnerPublicEffectsBaseline,
        1'000);
    auto hidden = arm(
        registered_driver::CaptureClassification::HiddenCandidate,
        10'000);
    mutator(baseline, hidden);
    refuses([&] {
        auto baseline_authority = mint(std::move(baseline));
        auto hidden_authority = mint(std::move(hidden));
        (void)FreshOwnerArmIsolationBridge::join(
            std::move(baseline_authority),
            std::move(hidden_authority));
    });
}

void happy() {
    static_assert(!std::copy_constructible<
                  FreshOwnerPrivateArmLaunchAuthority>);
    static_assert(std::move_constructible<
                  FreshOwnerPrivateArmLaunchAuthority>);
    static_assert(!std::copy_constructible<
                  FreshOwnerArmIsolationAuthority>);
    static_assert(std::move_constructible<
                  FreshOwnerArmIsolationAuthority>);

    auto baseline = mint(arm(
        registered_driver::CaptureClassification::
            ExplicitOwnerPublicEffectsBaseline,
        1'000));
    auto hidden = mint(arm(
        registered_driver::CaptureClassification::HiddenCandidate,
        10'000));
    auto joined = FreshOwnerArmIsolationBridge::join(
        std::move(baseline), std::move(hidden));
    auto moved = FreshOwnerArmIsolationAuthority(std::move(joined));
    auto baseline_residual = moved.take_baseline_residual();
    auto hidden_residual = moved.take_hidden_candidate_residual();
    static_assert(!std::copy_constructible<
                  FreshOwnerArmIsolationResidualAuthority>);
    static_assert(std::move_constructible<
                  FreshOwnerArmIsolationResidualAuthority>);
    (void)baseline_residual;
    (void)hidden_residual;
    refuses([&] { (void)moved.take_baseline_residual(); });
    refuses([&] { (void)moved.take_hidden_candidate_residual(); });
}

void replay() {
    auto baseline = mint(arm(
        registered_driver::CaptureClassification::
            ExplicitOwnerPublicEffectsBaseline,
        1'000));
    auto hidden = mint(arm(
        registered_driver::CaptureClassification::HiddenCandidate,
        10'000));
    auto joined = FreshOwnerArmIsolationBridge::join(
        std::move(baseline), std::move(hidden));
    (void)joined;

    auto replacement_hidden = mint(arm(
        registered_driver::CaptureClassification::HiddenCandidate,
        20'000));
    refuses([&] {
        (void)FreshOwnerArmIsolationBridge::join(
            std::move(baseline), std::move(replacement_hidden));
    });
    auto replacement_baseline = mint(arm(
        registered_driver::CaptureClassification::
            ExplicitOwnerPublicEffectsBaseline,
        30'000));
    refuses([&] {
        (void)FreshOwnerArmIsolationBridge::join(
            std::move(replacement_baseline),
            std::move(replacement_hidden));
    });

    auto aliased = mint(arm(
        registered_driver::CaptureClassification::HiddenCandidate,
        40'000));
    refuses([&] {
        (void)FreshOwnerArmIsolationBridge::join(
            std::move(aliased), std::move(aliased));
    });
}

void logical_owner_collision() {
    // Same-index inequality would miss this full role rotation. Compare the
    // two unordered owner sets instead.
    cross_arm_refuses([](auto& baseline, auto& hidden) {
        hidden.logical_owner_ids = {
            baseline.logical_owner_ids[1],
            baseline.logical_owner_ids[2],
            baseline.logical_owner_ids[0],
        };
    });
    cross_arm_refuses([](auto&, auto& hidden) {
        hidden.logical_owner_ids[2] = hidden.logical_owner_ids[0];
    });
}

void process_root_pid_collision() {
    cross_arm_refuses([](auto& baseline, auto& hidden) {
        hidden.process_authority_identity =
            baseline.process_authority_identity;
    });
    cross_arm_refuses([](auto& baseline, auto& hidden) {
        hidden.supervisor_session_identity =
            baseline.supervisor_session_identity;
    });
    cross_arm_refuses([](auto& baseline, auto& hidden) {
        hidden.child_pids[0] = baseline.child_pids[2];
    });
    cross_arm_refuses([](auto& baseline, auto& hidden) {
        hidden.child_sessions[2] = baseline.child_sessions[0];
    });
    cross_arm_refuses([](auto& baseline, auto& hidden) {
        hidden.root_slots[1] = baseline.root_slots[2];
    });
}

void tls_contract_collision() {
    cross_arm_refuses([](auto& baseline, auto& hidden) {
        hidden.contract_ids[0] = baseline.contract_ids[5];
    });
    cross_arm_refuses([](auto& baseline, auto& hidden) {
        hidden.owner_tls_cert_ids[4] = baseline.owner_tls_cert_ids[1];
    });
    cross_arm_refuses([](auto& baseline, auto& hidden) {
        hidden.owner_tls_spki_ids[2] = baseline.owner_tls_spki_ids[3];
    });
    cross_arm_refuses([](auto& baseline, auto& hidden) {
        for (unsigned owner = 0; owner < 3; ++owner)
            hidden.server_tls_cert_ids[owner][1] =
                baseline.server_tls_cert_ids[5][2];
    });
    cross_arm_refuses([](auto& baseline, auto& hidden) {
        for (unsigned owner = 0; owner < 3; ++owner)
            hidden.server_tls_spki_ids[3 + owner][2] =
                baseline.server_tls_spki_ids[0][0];
    });
}

void classification_substitution() {
    cross_arm_refuses([](auto&, auto& hidden) {
        hidden.classification = registered_driver::CaptureClassification::
            ExplicitOwnerPublicEffectsBaseline;
    });
    cross_arm_refuses([](auto& baseline, auto&) {
        baseline.classification =
            registered_driver::CaptureClassification::HiddenCandidate;
    });
}

void status() {
    const auto value = fresh_owner_arm_isolation_source_status();
    assert(value.schema ==
           "kpi-fresh-owner-arm-isolation-source-status/v1");
    assert(value.status == "SOURCE_ONLY_CONFIGURED0");
    assert(value.exact_baseline_hidden_pair);
    assert(value.full_cross_set_private_disjointness);
    assert(value.mandatory_r1_residual_gate);
    assert(value.role_permutation_shortcut == false);
    assert(value.public_or_durable_raw_identifier_output == false);
    assert(value.production_paired_trial_callsite == false);
    assert(value.registered_driver_configured == false);
    assert(value.launch_authorized == false);
}

} // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    const std::string_view scenario(argv[1]);
    if (scenario == "happy") happy();
    else if (scenario == "replay") replay();
    else if (scenario == "logical-owner") logical_owner_collision();
    else if (scenario == "process-root-pid") process_root_pid_collision();
    else if (scenario == "tls-contract") tls_contract_collision();
    else if (scenario == "classification") classification_substitution();
    else if (scenario == "status") status();
    else assert(false);
    return 0;
}
