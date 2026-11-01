#include "../../p1_mascot_secret_source_capture.hpp"
#include "OT/NPartyTripleGenerator.hpp"

#include <algorithm>
#include <cassert>
#include <filesystem>
#include <string>
#include <vector>

namespace source = kpb_mp_spdz_p1_mascot;

namespace {

struct ZeroScalarCompleteKey final {
    bool operator==(int value) const noexcept { return value == 0; }
    void pack(octetStream& output) const {
        static constexpr unsigned char whole_object[]{0, 0xa5, 0x5a};
        output.append(whole_object, sizeof(whole_object));
    }
};

struct ThrowingMultiplier final : OTMultiplierBase {
    bool& destroyed;
    std::string path;
    ThrowingMultiplier(bool& destroyed, std::string path)
        : destroyed(destroyed), path(std::move(path)) {}
    ~ThrowingMultiplier() override { destroyed = true; }
    void multiply() override {
        auto outcome = source::unlink_cache_for_abort(
            path, source::AbortClass::OtMultiplierFailure);
        assert(outcome.succeeded);
        throw std::runtime_error("selected-worker-failure");
    }
    void multiply_raw() override {}
};

struct IdleMultiplier final : OTMultiplierBase {
    void multiply() override {
        outbox.push({});
        MultJob job;
        while (inbox.pop(job)) {}
    }
    void multiply_raw() override {}
};

class WorkerSink final : public source::state::MascotSecretStateHook {
public:
    unsigned unavailable{};
    std::vector<source::state::MascotSecretAbortEventKind> abort_kinds;
    WorkerSink() : MascotSecretStateHook(TestOnlyConstruction{}) {}
    bool record_mascot_secret_event(
            const source::state::MascotSecretEventView&) noexcept override {
        return true;
    }
    bool record_mascot_secret_abort_event(
            const source::state::MascotSecretAbortEventView& event)
            noexcept override {
        try {
            (void)source::state::encode_mascot_secret_abort_event(event);
            abort_kinds.push_back(event.kind);
            return true;
        } catch (...) {
            return false;
        }
    }
    void mascot_secret_unavailable_noexcept() noexcept override {
        ++unavailable;
    }
};

} // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    const std::filesystem::path root(argv[1]);
    std::filesystem::current_path(root);
    std::filesystem::create_directory("Player-Data");

    // Exact selected get_ot_secrets_filename() shape: PREP_DIR already ends
    // in '/', and the pinned helper appends another '/'.
    const std::string file = "Player-Data//Mascot-Secrets-test-P1-3";
    const std::vector<unsigned char> exact{
        5, 0, 0, 0, 0, 0, 0, 0, 9, 8, 7, 6, 5, 4};

    bool worker_destroyed = false;
    {
        WorkerSink sink;
        auto scope = source::state::MascotSecretStateScopeFactoryBridge::
            test_only_install(sink, 1, 3, true, "selected-P1", "17");
        const std::string abort_path =
            "Player-Data//Mascot-Secrets-worker-abort-P1-3";
        auto abort_seed = source::detail::capture_write(abort_path, exact);
        assert(abort_seed.result ==
               source::state::MascotFileResult::Captured);
        const std::vector<unsigned char> complete{1, 2, 3};
        const std::vector<unsigned char> scalar{9, 8};
        const std::vector<unsigned char> zero_complete{0};
        assert(source::state::MascotSecretStateSourceBridge::
            scalar_state_begin(
                "Mascot-Secrets/test", abort_path, 1000, 4, 40,
                true, false, scalar, scalar));
        assert(source::state::MascotSecretStateSourceBridge::setup_begin(
            "Mascot-Secrets/test", abort_path, 1000, 4, 40,
            true, false, true, complete));
        assert(source::state::MascotSecretStateSourceBridge::
            static_installed(
                true, complete, scalar, scalar, scalar));

        ThrowingMultiplier worker(worker_destroyed, abort_path);
        IdleMultiplier peer;
        worker.p1_mascot_capture = true;
        worker.p1_mascot_worker_ordinal = 0;
        worker.p1_mascot_worker_epoch =
            source::state::MascotSecretStateSourceBridge::
                register_ot_worker_noexcept(&worker, 0, 2);
        peer.p1_mascot_capture = true;
        peer.p1_mascot_worker_ordinal = 1;
        peer.p1_mascot_worker_epoch =
            source::state::MascotSecretStateSourceBridge::
                register_ot_worker_noexcept(&peer, 1, 2);
        assert(worker.p1_mascot_worker_epoch != 0);
        assert(peer.p1_mascot_worker_epoch != 0);
        assert(::pthread_create(
            &worker.thread, nullptr, run_ot_thread<int>, &worker) == 0);
        worker.p1_mascot_thread_created = true;
        assert(::pthread_create(
            &peer.thread, nullptr, run_ot_thread<int>, &peer) == 0);
        peer.p1_mascot_thread_created = true;
        (void)worker.outbox.pop();
        (void)peer.outbox.pop();
        assert(worker.failure != nullptr);
        source::state::MascotSecretStateSourceBridge::
            root_worker_failure_observed_noexcept(
                &worker, worker.p1_mascot_worker_epoch);
        bool root_rethrew = false;
        try {
            std::rethrow_exception(worker.failure);
        } catch (const std::runtime_error& error) {
            root_rethrew =
                std::string(error.what()) == "selected-worker-failure";
        }
        assert(root_rethrew);
        assert(!worker_destroyed);
        peer.inbox.stop();
        assert(::pthread_join(worker.thread, nullptr) == 0);
        source::state::MascotSecretStateSourceBridge::
            ot_worker_joined_noexcept(
                &worker, worker.p1_mascot_worker_epoch);
        assert(::pthread_join(peer.thread, nullptr) == 0);
        source::state::MascotSecretStateSourceBridge::
            ot_worker_joined_noexcept(&peer, peer.p1_mascot_worker_epoch);
        assert(!worker_destroyed);
        assert(source::state::MascotSecretStateSourceBridge::teardown(
            true, complete, scalar, false, zero_complete, scalar,
            scalar, scalar));
        assert(sink.unavailable == 0);
        scope.reset();
        assert(sink.abort_kinds.front() ==
               source::state::MascotSecretAbortEventKind::CacheUnlink);
        assert(sink.abort_kinds.back() ==
               source::state::MascotSecretAbortEventKind::AbortTerminal);
        assert(std::count(
            sink.abort_kinds.begin(), sink.abort_kinds.end(),
            source::state::MascotSecretAbortEventKind::WorkerTerminal) == 2);
        assert(std::count(
            sink.abort_kinds.begin(), sink.abort_kinds.end(),
            source::state::MascotSecretAbortEventKind::WorkerJoined) == 2);
    }
    assert(worker_destroyed);

    auto zero_scalar_with_ot =
        source::packed_complete_key(ZeroScalarCompleteKey{});
    assert((std::vector<unsigned char>(
                zero_scalar_with_ot.source_view().begin(),
                zero_scalar_with_ot.source_view().end()) ==
            std::vector<unsigned char>{0, 0xa5, 0x5a}));

    auto missing = source::detail::capture_read(file);
    assert(missing.result ==
           source::state::MascotFileResult::Missing);
    assert(missing.operation_errno != 0);
    assert(missing.bytes.empty());

    auto written = source::detail::capture_write(file, exact);
    assert(written.result ==
           source::state::MascotFileResult::Captured);
    assert(written.fsync_result ==
           source::state::MascotStepResult::Succeeded);
    assert(written.rename_result ==
           source::state::MascotStepResult::NotAttempted);
    assert(written.unlink_result ==
           source::state::MascotStepResult::NotAttempted);
    assert(written.bytes == exact);
    assert(written.descriptor_before.device ==
           written.descriptor_after.device);
    assert(written.descriptor_before.inode ==
           written.reopened_descriptor.inode);

    auto read = source::detail::capture_read(file);
    assert(read.result == source::state::MascotFileResult::Captured);
    assert(read.bytes == exact);
    assert(read.path_lstat_before == read.path_lstat_after);
    assert(read.descriptor_before == read.descriptor_after);
    assert(read.descriptor_after == read.reopened_descriptor);

    const std::filesystem::path link =
        "Player-Data/Mascot-Secrets-link-P1-3";
    std::filesystem::create_symlink(
        "Mascot-Secrets-test-P1-3", link);
    auto followed = source::detail::capture_read(link.string());
    assert(followed.result == source::state::MascotFileResult::Failed);
    assert(followed.no_follow);
    assert(followed.operation_errno != 0);
    assert(followed.bytes.empty());

    auto dotdot = source::detail::capture_read(
        "Player-Data/../Player-Data/Mascot-Secrets-test-P1-3");
    assert(dotdot.result == source::state::MascotFileResult::Failed);
    assert(dotdot.operation_errno == EINVAL);

    std::filesystem::create_directory("Player-Data/not-a-regular-file");
    auto directory = source::detail::capture_read(
        "Player-Data//not-a-regular-file");
    assert(directory.result == source::state::MascotFileResult::Failed);
    assert(directory.operation_errno == EINVAL);
    auto directory_write = source::detail::capture_write(
        "Player-Data//not-a-regular-file", exact);
    assert(directory_write.result == source::state::MascotFileResult::Failed);
    assert(directory_write.operation_errno == EINVAL);

    const std::string prep_directory =
        "Player-Data/missing-prep/3-p-256/";
    const std::string prep_file = prep_directory +
        "/Player-MAC-Keys-p-P1";
    auto prep_written = source::detail::capture_prep_mac_write(
        prep_file, prep_directory, exact);
    assert(prep_written.result ==
           source::state::MascotFileResult::Captured);
    assert(prep_written.parent_directory_result ==
           source::state::MascotStepResult::Succeeded);
    assert(prep_written.parent_directory_errno == 0);
    assert(prep_written.bytes == exact);
    assert(std::filesystem::is_regular_file(prep_file));

    std::filesystem::create_directory("outside-prep");
    std::filesystem::create_directory_symlink(
        "../outside-prep", "Player-Data/substituted-prep");
    const std::string substituted_directory =
        "Player-Data/substituted-prep/";
    const std::string substituted_prep_file = substituted_directory +
        "/Player-MAC-Keys-p-P1";
    auto prep_substituted = source::detail::capture_prep_mac_write(
        substituted_prep_file, substituted_directory, exact);
    assert(prep_substituted.result ==
           source::state::MascotFileResult::Failed);
    assert(prep_substituted.parent_directory_result ==
           source::state::MascotStepResult::Failed);
    assert(prep_substituted.parent_directory_errno != 0);
    assert(!std::filesystem::exists(
        "outside-prep/Player-MAC-Keys-p-P1"));

    auto prep_dotdot = source::detail::capture_prep_mac_write(
        "Player-Data/../outside-prep/Player-MAC-Keys-p-P1",
        "Player-Data/../outside-prep/", exact);
    assert(prep_dotdot.result ==
           source::state::MascotFileResult::Failed);
    assert(prep_dotdot.parent_directory_result ==
           source::state::MascotStepResult::Failed);
    assert(prep_dotdot.parent_directory_errno == EINVAL);

    const std::string abort_target =
        "Player-Data//Mascot-Secrets-abort-P1-3";
    auto abort_seed = source::detail::capture_write(abort_target, exact);
    assert(abort_seed.result == source::state::MascotFileResult::Captured);
    auto abort_removed = source::unlink_cache_for_abort(
        abort_target, source::AbortClass::OtMultiplierFailure);
    assert(abort_removed.succeeded);
    assert(abort_removed.operation_errno == 0);
    assert(source::detail::regular_file(
        abort_removed.path_lstat_before));
    assert(!abort_removed.path_lstat_after.present);

    auto abort_missing = source::unlink_cache_for_abort(
        abort_target, source::AbortClass::MacCheckFailure);
    assert(!abort_missing.succeeded);
    assert(abort_missing.operation_errno == ENOENT);

    auto abort_substituted = source::unlink_cache_for_abort(
        link.string(), source::AbortClass::OtMultiplierFailure);
    assert(!abort_substituted.succeeded);
    assert(abort_substituted.operation_errno == EINVAL);
    assert(std::filesystem::is_symlink(link));

    auto abort_directory = source::unlink_cache_for_abort(
        "Player-Data//not-a-regular-file",
        source::AbortClass::MacCheckFailure);
    assert(!abort_directory.succeeded);
    assert(abort_directory.operation_errno == EINVAL);

#ifdef KPI_P1_MASCOT_SECRET_SOURCE_CAPTURE_TEST_SETUP
    source::detail::set_test_fault(source::detail::TestFault::ShortRead);
    auto short_read = source::detail::capture_read(file);
    assert(short_read.result == source::state::MascotFileResult::Partial);
    assert(short_read.operation_errno == EIO);
    assert(short_read.bytes_transferred + 1 == exact.size());

    source::detail::set_test_fault(
        source::detail::TestFault::ReopenMismatch);
    auto substituted = source::detail::capture_read(file);
    assert(substituted.result == source::state::MascotFileResult::Failed);
    assert(substituted.operation_errno == EIO);
    assert(substituted.bytes == exact);

    const std::string fsync_path =
        "Player-Data//Mascot-Secrets-fsync-P1-3";
    source::detail::set_test_fault(
        source::detail::TestFault::FsyncFailure);
    auto fsync_failed = source::detail::capture_write(fsync_path, exact);
    assert(fsync_failed.bytes_transferred == exact.size());
    assert(fsync_failed.fsync_result ==
           source::state::MascotStepResult::Failed);
    assert(fsync_failed.fsync_errno == EIO);
    assert(fsync_failed.result == source::state::MascotFileResult::Failed);
#endif
}
