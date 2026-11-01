#include "bounded_setup_authority.hpp"

#include <cassert>
#include <cstdio>

using namespace kpb::bounded_setup;

int main(int argc, char** argv) {
    assert(argc == 3);
    try {
        const auto receipt = SourceOwnedBoundedSetupLauncher::preflight(
            argv[1], argv[2]);
        assert(receipt.source_closed_static_worker_exact);
        assert(receipt.aggregate_public_inputs_exact);
        assert(receipt.worker_bytes == 1745168);
        assert(receipt.swap_max_zero);
        assert(receipt.anonymous_private_outputs_supported);
        assert(receipt.missing_parent_artifacts == 60);
        assert(!receipt.production_plan_selected);
        assert(!receipt.full_setup_ready);
        assert(!receipt.s4_selected && !receipt.s12_selected);
        assert(!receipt.configured);
        std::printf(
            "{\"schema\":\"kpb-bounded-setup-preflight/v1\","
            "\"worker_bytes\":%llu,\"memory_limit_bytes\":%llu,"
            "\"memory_current_bytes\":%llu,"
            "\"host_memory_available_bytes\":%llu,"
            "\"output_available_bytes\":%llu,"
            "\"memory_bounded\":%s,\"memory_headroom\":%s,"
            "\"filesystem_headroom\":%s,"
            "\"production_plan_selected\":false,"
            "\"missing_parent_artifacts\":60,"
            "\"full_setup_ready\":false,\"configured\":false}\n",
            static_cast<unsigned long long>(receipt.worker_bytes),
            static_cast<unsigned long long>(
                receipt.cgroup_memory_limit_bytes),
            static_cast<unsigned long long>(
                receipt.cgroup_memory_current_bytes),
            static_cast<unsigned long long>(
                receipt.host_memory_available_bytes),
            static_cast<unsigned long long>(
                receipt.output_filesystem_available_bytes),
            receipt.cgroup_memory_finite_and_bounded ? "true" : "false",
            receipt.memory_headroom_sufficient ? "true" : "false",
            receipt.output_filesystem_headroom_sufficient ? "true" : "false");
        return 0;
    } catch (const SetupRefused&) {
        std::fputs("bounded setup preflight refused\n", stderr);
        return 2;
    }
}
