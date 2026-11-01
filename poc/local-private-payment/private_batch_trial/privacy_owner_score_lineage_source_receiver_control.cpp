#include "privacy_owner_score_lineage_source_authority.hpp"
#include "../mpc-prover/financial/registered_selected_producer_run_binding.hpp"

#include <cassert>
#include <cerrno>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string>
#include <unistd.h>

namespace source =
    kpb::measurement::score_output_lineage_source;
namespace registered = kpi::mpc::financial::registered_driver;

namespace {

registered::RegisteredSelectedProducerPrelaunchPlan plan(
        std::string_view selection) {
    static constexpr std::string_view run{
        "{\"schema\":\"kpb-source-owned-diagnostic-run/v1\","
        "\"selected\":true}\n"};
    registered::RegisteredSelectedProducerPrelaunchPlan result;
    result.classification = kpb::measurement::Classification::HiddenCandidate;
    result.comparison_selection = source::test_only_digest(selection);
    result.run_selection = source::test_only_digest(run);
    result.capture_trial_id =
        "22222222-2222-4222-8222-222222222222";
    result.measurement_attempt = source::measurement_attempt_from_outer_ascii(
        "actual-candidate-attempt-01");
    result.method = source::test_only_digest("frozen-method");
    result.source_closure = source::test_only_digest("source-closure");
    result.runtime = source::test_only_digest("runtime-closure");
    return result;
}

template<class Function>
void refuses(Function&& function) {
    bool refused{};
    try { function(); }
    catch (...) { refused = true; }
    assert(refused);
}

int sealed_copy(const char* path, bool executable) {
    const int source_fd = ::open(path, O_RDONLY | O_CLOEXEC);
    assert(source_fd >= 0);
    struct stat info{};
    assert(::fstat(source_fd, &info) == 0 && info.st_size > 0);
    const int writer = ::memfd_create(
        executable ? "kpb-lineage-worker" : "kpb-lineage-selection",
        MFD_CLOEXEC | MFD_ALLOW_SEALING);
    assert(writer >= 0);
    std::string buffer(static_cast<std::size_t>(info.st_size), '\0');
    std::size_t offset{};
    while (offset < buffer.size()) {
        const auto count = ::pread(source_fd, buffer.data() + offset,
                                   buffer.size() - offset,
                                   static_cast<off_t>(offset));
        if (count < 0 && errno == EINTR) continue;
        assert(count > 0);
        offset += static_cast<std::size_t>(count);
    }
    offset = 0;
    while (offset < buffer.size()) {
        const auto count = ::write(writer, buffer.data() + offset,
                                   buffer.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        assert(count > 0);
        offset += static_cast<std::size_t>(count);
    }
    assert(::fchmod(writer, executable ? 0500 : 0400) == 0);
    assert(::fcntl(writer, F_ADD_SEALS,
                   F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK |
                       F_SEAL_SEAL) == 0);
    const std::string proc = "/proc/self/fd/" + std::to_string(writer);
    const int reader = ::open(proc.c_str(), O_RDONLY | O_CLOEXEC);
    assert(reader >= 0);
    ::close(writer);
    ::close(source_fd);
    return reader;
}

} // namespace

int main(int argc, char** argv) {
    assert(argc == 4);
    const std::string mode(argv[1]);
    int selection = mode == "mutable-input"
        ? ::open(argv[2], O_RDONLY | O_CLOEXEC)
        : sealed_copy(argv[2], false);
    int worker = mode == "mutable-input"
        ? ::open(argv[3], O_RDONLY | O_CLOEXEC)
        : sealed_copy(argv[3], true);
    assert(selection >= 0 && worker >= 0);
    if (mode == "fd-collision") {
        const int safe_selection = ::fcntl(selection, F_DUPFD_CLOEXEC, 64);
        const int safe_worker = ::fcntl(worker, F_DUPFD_CLOEXEC, 64);
        assert(safe_selection >= 0 && safe_worker >= 0);
        assert(::dup3(safe_selection, 61, O_CLOEXEC) == 61);
        assert(::dup3(safe_worker, 60, O_CLOEXEC) == 60);
        ::close(safe_selection);
        ::close(safe_worker);
        ::close(selection);
        ::close(worker);
        selection = 61;
        worker = 60;
    }
    const std::string selection_raw{"exact-diagnostic-selection\n"};
    auto selected_plan = plan(selection_raw);
    if (mode == "cross-method")
        selected_plan.method[0] ^= 0x80;
    else if (mode == "cross-run")
        selected_plan.run_selection[0] ^= 0x80;
    else if (mode == "cross-source")
        selected_plan.source_closure[0] ^= 0x80;
    else if (mode == "cross-runtime")
        selected_plan.runtime[0] ^= 0x80;
    else if (mode == "cross-attempt-domain")
        selected_plan.measurement_attempt[0] ^= 0x80;
    else if (mode == "cross-trial")
        selected_plan.capture_trial_id =
            "11111111-1111-4111-8111-111111111111";
    else if (mode == "cross-class")
        selected_plan.classification =
            kpb::measurement::Classification::TransparentBaseline;
    auto binding = registered::
        RegisteredSelectedProducerPrelaunchBindingAuthority::
            test_only_lineage_binding(
                std::move(selected_plan), selection, worker);
    if (mode == "success" || mode == "fd-collision") {
        auto authenticated =
            source::PrivacyLaunchLineageSourceReceiverBridge::receive(binding);
        refuses([&] {
            (void)source::PrivacyLaunchLineageSourceReceiverBridge::receive(
                binding);
        });
        auto admitted = source::SelectedOwnerScoreLineageAdmissionBridge::admit(
            std::move(authenticated));
        const auto summary = source::SelectedOwnerScoreLineageAdmissionBridge::
            test_only_consume(std::move(admitted));
        assert(summary.method_sha256 == source::test_only_digest(
                   "frozen-method"));
        assert(summary.run_selection_sha256 == source::test_only_digest(
            "{\"schema\":\"kpb-source-owned-diagnostic-run/v1\","
            "\"selected\":true}\n"));
        assert(summary.diagnostic_selection_sha256 ==
               source::test_only_digest(selection_raw));
        assert(summary.trial_id ==
               "22222222-2222-4222-8222-222222222222");
        assert(summary.attempt_id == "actual-candidate-attempt-01");
    } else {
        refuses([&] {
            (void)source::PrivacyLaunchLineageSourceReceiverBridge::receive(
                binding);
        });
        refuses([&] {
            (void)source::PrivacyLaunchLineageSourceReceiverBridge::receive(
                binding);
        });
    }
}
