#include "p1_commitment_entropy_source_capture.hpp"

#include "Tools/Commit.h"

#include <array>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace kpi::mpc::p1_private_state;

namespace {

void need(bool value) {
    if (!value) throw std::runtime_error("commitment-entropy-control");
}

struct Record final {
    CommitmentEntropySourceSite site{};
    std::uint64_t owner{};
    std::uint64_t process{};
    std::uint64_t thread{};
    std::uint64_t object{};
    std::uint64_t before{};
    std::uint64_t after{};
    std::array<unsigned char, COMMITMENT_ENTROPY_BYTES> entropy{};
    std::vector<unsigned char> encoding;
};

class Hook final : public CommitmentEntropyStateHook {
public:
    std::vector<Record> records;
    unsigned terminal_count{};
    unsigned unavailable_count{};
    bool accept{true};
    bool terminal_accept{true};
    int rejection_marker_fd{-1};

    Hook() : CommitmentEntropyStateHook(TestOnlyConstruction{}) {}

    bool record_commitment_entropy(
            const CommitmentEntropyView& value) noexcept override {
        try {
            Record record{
                .site = value.source_site,
                .owner = value.commitment_owner,
                .process = value.logical_process_epoch,
                .thread = value.logical_thread_epoch,
                .object = value.object_epoch,
                .before = value.counter_before,
                .after = value.counter_after,
                .encoding = encode_commitment_entropy(value),
            };
            if (value.exact_entropy.size() != record.entropy.size())
                return false;
            std::memcpy(
                record.entropy.data(), value.exact_entropy.data(),
                record.entropy.size());
            records.push_back(std::move(record));
            if (!accept && rejection_marker_fd >= 0) {
                const unsigned char marker = 0xa7;
                if (::write(rejection_marker_fd, &marker, 1) != 1)
                    return false;
            }
            return accept;
        }
        catch (...) {
            return false;
        }
    }

    bool commitment_entropy_terminal_noexcept() noexcept override {
        ++terminal_count;
        return terminal_accept;
    }

    void commitment_entropy_unavailable_noexcept() noexcept override {
        ++unavailable_count;
    }
};

octetStream message() {
    static constexpr unsigned char bytes[] = {0x11, 0x22, 0x33, 0x44};
    octetStream result;
    result.append(bytes, sizeof(bytes));
    return result;
}

std::array<unsigned char, COMMITMENT_ENTROPY_BYTES> tail(
        const octetStream& value) {
    need(value.get_length() >= COMMITMENT_ENTROPY_BYTES);
    std::array<unsigned char, COMMITMENT_ENTROPY_BYTES> result{};
    std::memcpy(
        result.data(),
        value.get_data() + value.get_length() - result.size(),
        result.size());
    return result;
}

void normal_sources_and_explicit_worker() {
    const auto input = message();

    // Unselected/default execution remains behavior-compatible and records
    // nothing when no private capsule scope is installed.
    octetStream unselected_commitment;
    octetStream unselected_opening;
    Commit(unselected_commitment, unselected_opening, input, 1);

    Hook hook;
    auto scope = CommitmentEntropyScopeFactoryBridge::test_only_install(
        hook, 71, 101);

    octetStream commitment;
    octetStream opening;
    Commit(commitment, opening, input, 1);
    need(hook.records.size() == 1);
    need(hook.records[0].site ==
             CommitmentEntropySourceSite::LegacyCommitFunction &&
         hook.records[0].owner == 1 && hook.records[0].process == 71 &&
         hook.records[0].thread == 101 && hook.records[0].object == 1 &&
         hook.records[0].before == 0 && hook.records[0].after == 1 &&
         hook.records[0].entropy == tail(opening));

    Commitment object(1);
    object.commit(input);
    need(hook.records.size() == 2);
    need(hook.records[1].site ==
             CommitmentEntropySourceSite::CommitmentObject &&
         hook.records[1].thread == 101 && hook.records[1].object == 2 &&
         hook.records[1].before == 0 && hook.records[1].after == 1 &&
         hook.records[1].entropy == tail(object.open));

    std::atomic<bool> duplicate_epoch_refused{false};
    std::thread duplicate_epoch([&] {
        try {
            auto invalid =
                CommitmentEntropyScopeFactoryBridge::test_only_bind_thread(
                    101);
            (void)invalid;
        }
        catch (const std::runtime_error&) {
            duplicate_epoch_refused = true;
        }
    });
    duplicate_epoch.join();
    need(duplicate_epoch_refused);

    std::thread worker([&] {
        auto thread_scope =
            CommitmentEntropyScopeFactoryBridge::test_only_bind_thread(202);
        Commitment worker_object(2);
        worker_object.commit(input);
    });
    worker.join();
    need(hook.records.size() == 3);
    need(hook.records[2].site ==
             CommitmentEntropySourceSite::CommitmentObject &&
         hook.records[2].owner == 2 && hook.records[2].thread == 202 &&
         hook.records[2].object == 3 && hook.records[2].before == 1 &&
         hook.records[2].after == 2);

    for (const auto& record : hook.records) {
        const std::string_view encoded(
            reinterpret_cast<const char*>(record.encoding.data()),
            record.encoding.size());
        need(encoded.starts_with("KPI_P1_COMMITMENT_ENTROPY_STATE_V1\n"));
        need(encoded.find(commitment_entropy_source_domain(record.site)) !=
             std::string_view::npos);
    }
    need(std::move(scope).finish_noexcept());
    need(hook.terminal_count == 1 && hook.unavailable_count == 0);
}

void invalid_or_unbound_sources_poison() {
    {
        Hook hook;
        auto scope = CommitmentEntropyScopeFactoryBridge::test_only_install(
            hook, 72, 102);
        std::array<unsigned char, COMMITMENT_ENTROPY_BYTES - 1> short_value{};
        need(CommitmentEntropySourceBridge::test_only_record_legacy_commit(
                 1, short_value) == CommitmentEntropyRetainResult::Failed);
        need(!std::move(scope).finish_noexcept());
        need(hook.records.empty() && hook.unavailable_count == 1);
    }
    {
        Hook hook;
        auto scope = CommitmentEntropyScopeFactoryBridge::test_only_install(
            hook, 73, 103);
        std::atomic<CommitmentEntropyRetainResult> result{
            CommitmentEntropyRetainResult::NotRequired};
        std::thread worker([&] {
            std::array<unsigned char, COMMITMENT_ENTROPY_BYTES> bytes{};
            result = CommitmentEntropySourceBridge::
                test_only_record_object_commit(1, bytes);
        });
        worker.join();
        need(result == CommitmentEntropyRetainResult::Failed);
        need(!std::move(scope).finish_noexcept());
        need(hook.records.empty() && hook.unavailable_count == 1);
    }
    {
        Hook hook;
        auto scope = CommitmentEntropyScopeFactoryBridge::test_only_install(
            hook, 74, 104);
        std::array<unsigned char, COMMITMENT_ENTROPY_BYTES> bytes{};
        need(CommitmentEntropySourceBridge::test_only_record_legacy_commit(
                 -1, bytes) == CommitmentEntropyRetainResult::Failed);
        need(!std::move(scope).finish_noexcept());
        need(hook.unavailable_count == 1);
    }
}

void patched_callsite_refusal_is_fail_stop() {
    int marker_pipe[2]{};
    need(::pipe(marker_pipe) == 0);
    const auto child = ::fork();
    need(child >= 0);
    if (child == 0) {
        (void)::close(marker_pipe[0]);
        const rlimit no_core{.rlim_cur = 0, .rlim_max = 0};
        if (::setrlimit(RLIMIT_CORE, &no_core) != 0)
            ::_exit(91);
        Hook hook;
        hook.accept = false;
        hook.rejection_marker_fd = marker_pipe[1];
        auto scope = CommitmentEntropyScopeFactoryBridge::test_only_install(
            hook, 81, 111);
        octetStream commitment;
        octetStream opening;
        Commit(commitment, opening, message(), 1);
        (void)scope;
        ::_exit(92);
    }
    need(::close(marker_pipe[1]) == 0);
    int status{};
    while (::waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) need(false);
    }
    unsigned char marker{};
    const auto marker_size = ::read(marker_pipe[0], &marker, 1);
    need(::close(marker_pipe[0]) == 0);
    need(marker_size == 1 && marker == 0xa7 && WIFSIGNALED(status) &&
         WTERMSIG(status) == SIGABRT);
}

void lifecycle_refuses_overlap_and_live_worker_finish() {
    {
        Hook first;
        Hook second;
        auto scope = CommitmentEntropyScopeFactoryBridge::test_only_install(
            first, 75, 105);
        bool refused = false;
        try {
            auto duplicate =
                CommitmentEntropyScopeFactoryBridge::test_only_install(
                    second, 76, 106);
            (void)duplicate;
        }
        catch (const std::runtime_error&) {
            refused = true;
        }
        need(refused);
        need(std::move(scope).finish_noexcept());
    }
    {
        Hook hook;
        {
            auto dropped =
                CommitmentEntropyScopeFactoryBridge::test_only_install(
                    hook, 77, 107);
            (void)dropped;
        }
        need(hook.unavailable_count == 1 && hook.terminal_count == 0);
    }
    {
        Hook hook;
        auto scope = CommitmentEntropyScopeFactoryBridge::test_only_install(
            hook, 78, 108);
        std::mutex mutex;
        std::condition_variable condition;
        bool bound = false;
        bool release = false;
        std::thread worker([&] {
            auto binding =
                CommitmentEntropyScopeFactoryBridge::test_only_bind_thread(
                    208);
            {
                std::lock_guard lock(mutex);
                bound = true;
            }
            condition.notify_one();
            std::unique_lock lock(mutex);
            condition.wait(lock, [&] { return release; });
        });
        {
            std::unique_lock lock(mutex);
            condition.wait(lock, [&] { return bound; });
        }
        need(!std::move(scope).finish_noexcept());
        {
            std::lock_guard lock(mutex);
            release = true;
        }
        condition.notify_one();
        worker.join();
        need(hook.unavailable_count == 1);
    }
    {
        Hook hook;
        hook.terminal_accept = false;
        auto scope = CommitmentEntropyScopeFactoryBridge::test_only_install(
            hook, 82, 112);
        need(!std::move(scope).finish_noexcept());
        need(hook.terminal_count == 1 && hook.unavailable_count == 1);
    }
    {
        // A source scope may move, but only its installing source thread can
        // finalize it. The TLS binding itself is the authority; no pthread ID
        // or callback arrival order is accepted as a substitute.
        Hook hook;
        std::unique_ptr<CommitmentEntropySourceScope> foreign_scope;
        std::thread owner([&] {
            auto installed =
                CommitmentEntropyScopeFactoryBridge::test_only_install(
                    hook, 79, 109);
            foreign_scope =
                std::make_unique<CommitmentEntropySourceScope>(
                    std::move(installed));
        });
        owner.join();
        need(foreign_scope != nullptr);
        need(!std::move(*foreign_scope).finish_noexcept());
        need(hook.terminal_count == 0 && hook.unavailable_count == 1);
        foreign_scope.reset();
    }
    {
        // Likewise an explicit worker binding cannot be transferred to a
        // different thread merely by moving the C++ guard object.
        Hook hook;
        auto scope = CommitmentEntropyScopeFactoryBridge::test_only_install(
            hook, 80, 110);
        std::unique_ptr<CommitmentEntropyThreadScope> foreign_binding;
        std::thread worker([&] {
            auto binding =
                CommitmentEntropyScopeFactoryBridge::test_only_bind_thread(
                    210);
            foreign_binding =
                std::make_unique<CommitmentEntropyThreadScope>(
                    std::move(binding));
        });
        worker.join();
        need(foreign_binding != nullptr);
        foreign_binding.reset();
        need(!std::move(scope).finish_noexcept());
        need(hook.terminal_count == 0 && hook.unavailable_count == 1);
    }
}

void encoding_rejects_relabel_and_implicit_epochs() {
    std::array<unsigned char, COMMITMENT_ENTROPY_BYTES> bytes{};
    CommitmentEntropyView value{
        .source_site = CommitmentEntropySourceSite::LegacyCommitFunction,
        .commitment_owner = 1,
        .logical_process_epoch = 1,
        .logical_thread_epoch = 1,
        .object_epoch = 1,
        .counter_before = 0,
        .counter_after = 1,
        .exact_entropy = bytes,
    };
    const auto first = encode_commitment_entropy(value);
    value.source_site = CommitmentEntropySourceSite::CommitmentObject;
    const auto second = encode_commitment_entropy(value);
    need(first != second);
    value.logical_thread_epoch = 0;
    bool refused = false;
    try {
        (void)encode_commitment_entropy(value);
    }
    catch (const std::runtime_error&) {
        refused = true;
    }
    need(refused);

    const std::array manifest{
        CommitmentEntropyManifestEvent{
            CommitmentEntropySourceSite::LegacyCommitFunction, 1, 1},
        CommitmentEntropyManifestEvent{
            CommitmentEntropySourceSite::CommitmentObject, 1, 1},
    };
    const auto ordered = encode_commitment_entropy_manifest(manifest);
    auto reversed_manifest = manifest;
    std::swap(reversed_manifest[0], reversed_manifest[1]);
    need(ordered != encode_commitment_entropy_manifest(reversed_manifest));
    auto wrong_owner = manifest;
    ++wrong_owner[0].commitment_owner;
    need(ordered != encode_commitment_entropy_manifest(wrong_owner));
    auto wrong_thread = manifest;
    wrong_thread[0].logical_thread_epoch = 0;
    refused = false;
    try {
        (void)encode_commitment_entropy_manifest(wrong_thread);
    }
    catch (const std::runtime_error&) {
        refused = true;
    }
    need(refused);
}

} // namespace

int main() {
    normal_sources_and_explicit_worker();
    patched_callsite_refusal_is_fail_stop();
    invalid_or_unbound_sources_poison();
    lifecycle_refuses_overlap_and_live_worker_finish();
    encoding_rejects_relabel_and_implicit_epochs();

    static_assert(kCommitmentEntropySourceStatus.semantic_source_sites_fixed);
    static_assert(
        kCommitmentEntropySourceStatus.exact_opening_entropy_retained);
    static_assert(
        kCommitmentEntropySourceStatus.explicit_process_and_thread_epochs);
    static_assert(
        kCommitmentEntropySourceStatus.callback_order_thread_identity_absent);
    static_assert(!kCommitmentEntropySourceStatus.source_patch_selected);
    static_assert(!kCommitmentEntropySourceStatus.capsule_family_adapter);
    static_assert(!kCommitmentEntropySourceStatus.selected_role1_installation);
    static_assert(!kCommitmentEntropySourceStatus.complete_mp_spdz_prng_family);
    static_assert(!kCommitmentEntropySourceStatus.complete_corrupt_p1_view);
    static_assert(!kCommitmentEntropySourceStatus.configured);
}
