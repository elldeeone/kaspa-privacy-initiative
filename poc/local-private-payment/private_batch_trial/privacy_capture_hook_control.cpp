#include "privacy_capture_hook.hpp"

#include <array>
#include <fcntl.h>
#include <iostream>
#include <iterator>
#include <string>
#include <unistd.h>
#include <vector>

namespace {
using namespace kpb::capture;

std::string repeated(const std::string& pair) {
    std::string result;
    for (unsigned index = 0; index < 32; ++index) result += pair;
    return result;
}

Binding round_one(unsigned classification = 1) {
    return {
        "33333333-3333-4333-8333-333333333333",
        repeated("31"), repeated("15"),
        "22222222-2222-4222-8222-222222222222",
        "4a4bc3cecb21d11fcbdd2784f0199d781e266d231942fa6d3bcd25670c237d02",
        classification, repeated("43"), repeated("44"),
    };
}

RunBinding round_one_run(unsigned classification = 1) {
    const auto selected = round_one(classification);
    return {selected.attempt_id, selected.cohort_sha256,
            selected.financial_run_id, selected.capture_identity,
            selected.construction_classification,
            selected.construction_attempt_sha256,
            selected.capture_plan_sha256};
}

ExplicitOwnerPublicEffects explicit_effects() {
    const std::array<std::string, 3> nullifiers{
        "6500000000000000000000000000000000000000000000000000000000000000",
        "6600000000000000000000000000000000000000000000000000000000000000",
        "6700000000000000000000000000000000000000000000000000000000000000",
    };
    const std::array<std::array<std::string, 2>, 3> tuples{{
        {"7f478ad54b53ed976f694e0c539b548527196b74cffd2f2abfc2efc6b7af1b65",
         "c946eb7cbae77146751602bf555d66a652d58f592b550c851bd9c18b9c95b036"},
        {"2a1cb37437186ad27ffb601a0073ccc65e35ff386ee2400f2c68241bfdcc31e6",
         "8bca61d0dab726a0fee5a99f68479f4146e01a0709b461e2b6ddb1dfd961e70e"},
        {"707645a27ff40346ab6e87438576824cdf1c2f533eaaff2e5ab43d70b03d1303",
         "ac97f6036e3247bb4ed2c2b937dc1ecc7bf337b92b3962b51535975a6d2ef7c6"},
    }};
    ExplicitOwnerPublicEffects result{
        .run_sha256 = repeated("15"),
        .trial_sha256 = repeated("41"),
        .attempt_sha256 = repeated("43"),
        .cohort_sha256 = repeated("31"),
        .capture_plan_sha256 = repeated("44"),
        .projection_sha256 =
            "4a4bc3cecb21d11fcbdd2784f0199d781e266d231942fa6d3bcd25670c237d02",
        .context_sha256 =
            "547181fe60333d2ae599076d39bcfae4377bfdf611e4b9669bff65585bc4040b",
    };
    for (unsigned owner = 0; owner < result.owners.size(); ++owner) {
        result.owners[owner] = ExplicitOwnerPublicEffect{
            .owner_component = owner,
            .owner_contract_sha256 =
                repeated(std::to_string(owner + 4) + "0"),
            .nf_hex32 = nullifiers[owner],
            .tuple_sha256 = tuples[owner],
        };
    }
    return result;
}

void alias_stdout(int target) {
    if (::dup2(STDOUT_FILENO, target) != target) throw CaptureRefused();
}

template<class Hook>
void valid_dispatcher(Hook& hook, bool finish = true) {
    hook.listeners_ready(100);
    for (unsigned owner = 0; owner < 3; ++owner) {
        hook.owner_connected(owner, 101 + 2 * owner);
        hook.owner_upload_complete(owner, 102 + 2 * owner, 84333120);
    }
    hook.aggregate_release(107);
    hook.outbound_route(108, std::string(64, '1'));
    if (finish) hook.close_complete();
}

int run(const std::string& scenario) {
    if (scenario == "projection") {
        alias_stdout(20);
        std::vector<unsigned char> body{
            std::istreambuf_iterator<char>(std::cin), {}};
        ProjectionHook<20, 1> hook(round_one());
        hook.write_and_close(body); return 0;
    }
    if (scenario == "dispatcher") {
        alias_stdout(22);
        DispatcherHook<22, 1,
            ReleasePolicy::SecretPermutationIndependent> hook(round_one());
        valid_dispatcher(hook); return 0;
    }
    if (scenario == "deferred-dispatcher") {
        alias_stdout(22);
        DispatcherHook<22, 1,
            ReleasePolicy::SecretPermutationIndependent> hook(round_one_run());
        hook.listeners_ready(100);
        for (unsigned owner = 0; owner < 3; ++owner) {
            hook.owner_connected(owner, 101 + 2 * owner);
            hook.owner_upload_complete(owner, 102 + 2 * owner, 84333120);
        }
        hook.bind_projection(round_one().projection_sha256);
        hook.aggregate_release(107);
        hook.outbound_route(108, std::string(64, '1'));
        hook.close_complete(); return 0;
    }
    if (scenario == "explicit-dispatcher") {
        alias_stdout(22);
        DispatcherHook<22, 1,
            ReleasePolicy::ExplicitOwnerPublicEffects> hook(round_one_run(2));
        hook.listeners_ready(100);
        for (unsigned owner = 0; owner < 3; ++owner) {
            hook.owner_connected(owner, 101 + 2 * owner);
            hook.owner_upload_complete(owner, 102 + 2 * owner, 84333120);
        }
        hook.bind_projection(round_one().projection_sha256);
        hook.aggregate_release(107);
        hook.explicit_owner_public_effects(108, explicit_effects());
        hook.outbound_route(109, std::string(64, '1'));
        hook.close_complete(); return 0;
    }
    if (scenario == "explicit-on-secret-policy") {
        alias_stdout(22);
        DispatcherHook<22, 1,
            ReleasePolicy::SecretPermutationIndependent> hook(round_one());
        hook.listeners_ready(100);
        for (unsigned owner = 0; owner < 3; ++owner) {
            hook.owner_connected(owner, 101 + 2 * owner);
            hook.owner_upload_complete(owner, 102 + 2 * owner, 84333120);
        }
        hook.aggregate_release(107);
        hook.explicit_owner_public_effects(108, explicit_effects());
        return 0;
    }
    if (scenario == "missing-explicit-before-route") {
        alias_stdout(22);
        DispatcherHook<22, 1,
            ReleasePolicy::ExplicitOwnerPublicEffects> hook(round_one(2));
        hook.listeners_ready(100);
        for (unsigned owner = 0; owner < 3; ++owner) {
            hook.owner_connected(owner, 101 + 2 * owner);
            hook.owner_upload_complete(owner, 102 + 2 * owner, 84333120);
        }
        hook.aggregate_release(107);
        hook.outbound_route(108, std::string(64, '1'));
        return 0;
    }
    if (scenario == "duplicate-explicit") {
        alias_stdout(22);
        DispatcherHook<22, 1,
            ReleasePolicy::ExplicitOwnerPublicEffects> hook(round_one(2));
        hook.listeners_ready(100);
        for (unsigned owner = 0; owner < 3; ++owner) {
            hook.owner_connected(owner, 101 + 2 * owner);
            hook.owner_upload_complete(owner, 102 + 2 * owner, 84333120);
        }
        hook.aggregate_release(107);
        hook.explicit_owner_public_effects(108, explicit_effects());
        hook.explicit_owner_public_effects(109, explicit_effects());
        return 0;
    }
    if (scenario == "reversed-explicit-pair") {
        alias_stdout(22);
        DispatcherHook<22, 1,
            ReleasePolicy::ExplicitOwnerPublicEffects> hook(round_one(2));
        hook.listeners_ready(100);
        for (unsigned owner = 0; owner < 3; ++owner) {
            hook.owner_connected(owner, 101 + 2 * owner);
            hook.owner_upload_complete(owner, 102 + 2 * owner, 84333120);
        }
        hook.aggregate_release(107);
        auto value = explicit_effects();
        std::swap(value.owners[1].tuple_sha256[0],
                  value.owners[1].tuple_sha256[1]);
        hook.explicit_owner_public_effects(108, value);
        return 0;
    }
    if (scenario == "wrong-explicit-attempt") {
        alias_stdout(22);
        DispatcherHook<22, 1,
            ReleasePolicy::ExplicitOwnerPublicEffects> hook(round_one(2));
        hook.listeners_ready(100);
        for (unsigned owner = 0; owner < 3; ++owner) {
            hook.owner_connected(owner, 101 + 2 * owner);
            hook.owner_upload_complete(owner, 102 + 2 * owner, 84333120);
        }
        hook.aggregate_release(107);
        auto value = explicit_effects();
        value.attempt_sha256 = repeated("46");
        hook.explicit_owner_public_effects(108, value);
        return 0;
    }
    if (scenario == "wrong-explicit-capture-plan") {
        alias_stdout(22);
        DispatcherHook<22, 1,
            ReleasePolicy::ExplicitOwnerPublicEffects> hook(round_one(2));
        hook.listeners_ready(100);
        for (unsigned owner = 0; owner < 3; ++owner) {
            hook.owner_connected(owner, 101 + 2 * owner);
            hook.owner_upload_complete(owner, 102 + 2 * owner, 84333120);
        }
        hook.aggregate_release(107);
        auto value = explicit_effects();
        value.capture_plan_sha256 = repeated("47");
        hook.explicit_owner_public_effects(108, value);
        return 0;
    }
    if (scenario == "hidden-binding-explicit-policy") {
        alias_stdout(22);
        DispatcherHook<22, 1,
            ReleasePolicy::ExplicitOwnerPublicEffects> hook(round_one_run(1));
        (void)hook;
        return 0;
    }
    if (scenario == "baseline-binding-secret-policy") {
        alias_stdout(22);
        DispatcherHook<22, 1,
            ReleasePolicy::SecretPermutationIndependent> hook(round_one_run(2));
        (void)hook;
        return 0;
    }
    if (scenario == "missing-projection") {
        alias_stdout(22);
        DispatcherHook<22, 1,
            ReleasePolicy::SecretPermutationIndependent> hook(round_one_run());
        hook.listeners_ready(100);
        for (unsigned owner = 0; owner < 3; ++owner) {
            hook.owner_connected(owner, 101 + 2 * owner);
            hook.owner_upload_complete(owner, 102 + 2 * owner, 84333120);
        }
        hook.aggregate_release(107); return 0;
    }
    if (scenario == "wrong-fd") {
        (void)::close(22);
        DispatcherHook<22, 1,
            ReleasePolicy::SecretPermutationIndependent> hook(round_one());
        (void)hook; return 0;
    }
    if (scenario == "wrong-order") {
        alias_stdout(22);
        DispatcherHook<22, 1,
            ReleasePolicy::SecretPermutationIndependent> hook(round_one());
        hook.owner_upload_complete(0, 100, 84333120); return 0;
    }
    if (scenario == "duplicate-end") {
        alias_stdout(22);
        DispatcherHook<22, 1,
            ReleasePolicy::SecretPermutationIndependent> hook(round_one());
        valid_dispatcher(hook); hook.close_complete(); return 0;
    }
    if (scenario == "extra-event") {
        alias_stdout(22);
        DispatcherHook<22, 1,
            ReleasePolicy::SecretPermutationIndependent> hook(round_one());
        valid_dispatcher(hook);
        hook.outbound_route(109, std::string(64, '2')); return 0;
    }
    if (scenario == "unavailable-consumer") {
        std::array<int, 2> descriptors{};
        if (::pipe2(descriptors.data(), O_CLOEXEC) != 0)
            throw CaptureRefused();
        (void)::close(descriptors[0]);
        if (descriptors[1] != 22) {
            if (::dup2(descriptors[1], 22) != 22) throw CaptureRefused();
            (void)::close(descriptors[1]);
        }
        DispatcherHook<22, 1,
            ReleasePolicy::SecretPermutationIndependent> hook(round_one());
        (void)hook; return 0;
    }
    throw CaptureRefused();
}
} // namespace

int main(int argc, char** argv) {
    try {
        if (argc != 2) throw CaptureRefused();
        return run(argv[1]);
    } catch (...) {
        static constexpr char message[] = "KPB_CAPTURE_HOOK_REFUSED\n";
        const auto ignored = ::write(
            STDERR_FILENO, message, sizeof(message) - 1);
        (void)ignored;
        return 78;
    }
}
