#include "financial/registered_fresh_trial_history_ledger.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <csignal>
#include <cstdint>
#include <fcntl.h>
#include <openssl/sha.h>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using namespace kpi::mpc::financial::registered_driver;
using namespace kpi::mpc::financial::registered_driver::attempt_history;

namespace {

Digest id(unsigned char value) {
    Digest result{};
    result.fill(value);
    return result;
}

Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    assert(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return result;
}

Digest trial_identity(std::string_view value) {
    constexpr std::string_view domain =
        "KPB_REGISTERED_TRIAL_UUID_IDENTITY_V1\n";
    std::vector<unsigned char> bytes(domain.begin(), domain.end());
    const auto size = static_cast<std::uint64_t>(value.size());
    for (unsigned shift = 0; shift < 64; shift += 8)
        bytes.push_back(static_cast<unsigned char>(size >> shift));
    bytes.insert(bytes.end(), value.begin(), value.end());
    return hash(bytes);
}

void be32(unsigned char* out, std::uint32_t value) {
    for (unsigned index = 0; index < 4; ++index)
        out[index] = static_cast<unsigned char>(value >> (8 * (3 - index)));
}

void be64(unsigned char* out, std::uint64_t value) {
    for (unsigned index = 0; index < 8; ++index)
        out[index] = static_cast<unsigned char>(value >> (8 * (7 - index)));
}

std::vector<unsigned char> frame(
        unsigned char type, std::uint64_t sequence,
        std::span<const unsigned char> payload) {
    std::vector<unsigned char> result(112 + payload.size());
    std::copy_n(reinterpret_cast<const unsigned char*>("KPBP1C03"), 8,
                result.begin());
    result[8] = type;
    result[9] = 1;
    result[10] = 3;
    result[11] = 0xff;
    result[12] = 3;
    be64(result.data() + 16, 1'000 + sequence);
    be64(result.data() + 24, sequence);
    be64(result.data() + 32, sequence);
    be32(result.data() + 40, 0);
    be32(result.data() + 44, static_cast<std::uint32_t>(payload.size()));
    const auto payload_hash = hash(payload);
    std::copy(payload_hash.begin(), payload_hash.end(), result.begin() + 80);
    std::copy(payload.begin(), payload.end(), result.begin() + 112);
    return result;
}

std::vector<unsigned char> complete_c03() {
    const std::array<unsigned char, 7> hello{1, 2, 3, 4, 5, 6, 7};
    auto result = frame(1, 0, hello);
    const auto end = frame(5, 1, {});
    result.insert(result.end(), end.begin(), end.end());
    return result;
}

TestOnlyAttemptBinding binding(unsigned round, std::string uuid,
                               unsigned char seed) {
    return {
        .round = round,
        .attempt_uuid = std::move(uuid),
        .financial_run = id(seed),
        .cohort = id(seed + 1),
        .capture_plan = id(seed + 2),
        .projection = id(seed + 3),
        .capture_source = id(0xd1),
        .capture_build = id(0xd2),
        .capture_runtime = id(0xd3),
        .capture_launcher = id(0xd4),
        .route_requirement = id(static_cast<unsigned char>(seed + 8)),
        .route_completion = id(seed + 8),
    };
}

template<class Operation>
bool refuses(Operation&& operation) {
    try { operation(); }
    catch (const AttemptHistoryRefused&) { return true; }
    return false;
}

} // namespace

int main() {
    constexpr std::string_view TRIAL =
        "6f87aef8-106f-4d0f-9ee8-35ab56885be7";
    const TestOnlyTrialBinding trial{
        .classification = static_cast<CaptureClassification>(1),
        .capture_trial_id = std::string(TRIAL),
        .trial_identity = trial_identity(TRIAL),
    };
    const auto complete = complete_c03();
    const auto header = frame(1, 0, std::array<unsigned char, 4>{1, 2, 3, 4});
    const std::vector<unsigned char> partial_header(
        header.begin(), header.begin() + 31);
    const auto make_failed_history = [&](
            std::string_view trial_id, std::string attempt_id,
            unsigned char seed) {
        auto selected = RegisteredTrialAttemptHistoryTestBridge::begin({
            .classification = static_cast<CaptureClassification>(1),
            .capture_trial_id = std::string(trial_id),
            .trial_identity = trial_identity(trial_id),
        });
        RegisteredTrialAttemptHistoryTestBridge::observe(
            selected, binding(1, std::move(attempt_id), seed),
            partial_header, partial_header.size(),
            TestOnlyChildDisposition::ExitNonzero, 7);
        return RegisteredTrialAttemptHistoryRecorder::seal_failed(
            std::move(selected));
    };

    auto success = RegisteredTrialAttemptHistoryTestBridge::begin(trial);
    RegisteredTrialAttemptHistoryTestBridge::observe(
        success,
        binding(1, "a3647d17-b5d7-46bc-86ac-8421f93cdb46", 0x19),
        complete, complete.size(), TestOnlyChildDisposition::ExitZero, 0);
    RegisteredTrialAttemptHistoryTestBridge::observe(
        success,
        binding(2, "7be6fa9e-1604-4d30-bc1d-29553a8b4607", 0x1b),
        complete, complete.size(), TestOnlyChildDisposition::ExitZero, 0);
    auto success_authority = RegisteredTrialAttemptHistoryRecorder::seal(
        std::move(success));
    const auto success_summary =
        RegisteredTrialAttemptHistoryTestBridge::consume(
            std::move(success_authority));
    const std::array<std::size_t, 2> success_indices{0, 1};
    assert(success_summary.rows.size() == 2 &&
           success_summary.final_indices == success_indices &&
           success_summary.rows[0].ordinal == 0 &&
           success_summary.rows[1].ordinal == 1 &&
           success_summary.rows[0].retry_ordinal == 0 &&
           success_summary.rows[1].retry_ordinal == 0 &&
           success_summary.rows[0].predecessor == Digest{} &&
           success_summary.rows[1].predecessor == Digest{} &&
           success_summary.rows[1].trial_predecessor ==
               success_summary.rows[0].attempt_identity &&
           success_summary.rows[0].outcome == AttemptOutcome::Complete &&
           success_summary.rows[1].outcome == AttemptOutcome::Complete &&
           success_summary.rows[0].sealed_c03_access_mode == O_RDONLY &&
           success_summary.rows[1].sealed_c03_access_mode == O_RDONLY);

    auto failed = RegisteredTrialAttemptHistoryTestBridge::begin(trial);
    RegisteredTrialAttemptHistoryTestBridge::observe(
        failed,
        binding(1, "94dd344f-8b1e-491a-96c0-25f96e358a10", 0x21),
        partial_header, partial_header.size(),
        TestOnlyChildDisposition::ExitNonzero, 7);
    auto failure_authority =
        RegisteredTrialAttemptHistoryRecorder::seal_failed(
            std::move(failed));
    const auto failed_summary =
        RegisteredTrialAttemptHistoryTestBridge::consume_failed(
            std::move(failure_authority));
    assert(failed_summary.rows.size() == 1 &&
           failed_summary.rows[0].outcome == AttemptOutcome::Refused &&
           failed_summary.rows[0].failure == AttemptFailure::PartialHeader &&
           failed_summary.rows[0].c03_bytes == partial_header.size() &&
           failed_summary.rows[0].c03_sha256 == hash(partial_header));

    auto no_same_trial_retry =
        RegisteredTrialAttemptHistoryTestBridge::begin(trial);
    RegisteredTrialAttemptHistoryTestBridge::observe(
        no_same_trial_retry,
        binding(1, "bc1a2ee0-576a-4410-8738-d5368044fe5d", 0x17),
        {}, 0, TestOnlyChildDisposition::ExitNonzero, 19);
    assert(refuses([&] {
        RegisteredTrialAttemptHistoryTestBridge::observe(
            no_same_trial_retry,
            binding(1, "e02236e7-2e6c-47fd-9e95-ca165f31e365", 0x18),
            complete, complete.size(), TestOnlyChildDisposition::ExitZero, 0);
    }));

    constexpr std::string_view FRESH_TRIAL =
        "11111111-1111-4111-8111-111111111111";
    auto fresh = RegisteredTrialAttemptHistoryTestBridge::begin({
        .classification = static_cast<CaptureClassification>(1),
        .capture_trial_id = std::string(FRESH_TRIAL),
        .trial_identity = trial_identity(FRESH_TRIAL),
    });
    RegisteredTrialAttemptHistoryTestBridge::observe(
        fresh,
        binding(1, "22222222-2222-4222-8222-222222222222", 0x31),
        complete, complete.size(), TestOnlyChildDisposition::ExitZero, 0);
    RegisteredTrialAttemptHistoryTestBridge::observe(
        fresh,
        binding(2, "33333333-3333-4333-8333-333333333333", 0x41),
        complete, complete.size(), TestOnlyChildDisposition::ExitZero, 0);
    const auto fresh_summary = RegisteredTrialAttemptHistoryTestBridge::consume(
        RegisteredTrialAttemptHistoryRecorder::seal(std::move(fresh)));
    assert(fresh_summary.history_identity != success_summary.history_identity);

    constexpr std::string_view LEDGER_FAILED_TRIAL =
        "44444444-4444-4444-8444-444444444444";
    auto ledger_failed = RegisteredTrialAttemptHistoryTestBridge::begin({
        .classification = static_cast<CaptureClassification>(1),
        .capture_trial_id = std::string(LEDGER_FAILED_TRIAL),
        .trial_identity = trial_identity(LEDGER_FAILED_TRIAL),
    });
    RegisteredTrialAttemptHistoryTestBridge::observe(
        ledger_failed,
        binding(1, "55555555-5555-4555-8555-555555555555", 0x51),
        partial_header, partial_header.size(),
        TestOnlyChildDisposition::ExitNonzero, 17);
    auto failed_for_ledger =
        RegisteredTrialAttemptHistoryRecorder::seal_failed(
            std::move(ledger_failed));

    constexpr std::string_view LEDGER_SUCCESS_TRIAL =
        "66666666-6666-4666-8666-666666666666";
    auto ledger_success = RegisteredTrialAttemptHistoryTestBridge::begin({
        .classification = static_cast<CaptureClassification>(1),
        .capture_trial_id = std::string(LEDGER_SUCCESS_TRIAL),
        .trial_identity = trial_identity(LEDGER_SUCCESS_TRIAL),
    });
    RegisteredTrialAttemptHistoryTestBridge::observe(
        ledger_success,
        binding(1, "77777777-7777-4777-8777-777777777777", 0x61),
        complete, complete.size(), TestOnlyChildDisposition::ExitZero, 0);
    RegisteredTrialAttemptHistoryTestBridge::observe(
        ledger_success,
        binding(2, "88888888-8888-4888-8888-888888888888", 0x71),
        complete, complete.size(), TestOnlyChildDisposition::ExitZero, 0);
    auto success_for_ledger = RegisteredTrialAttemptHistoryRecorder::seal(
        std::move(ledger_success));

    auto ledger = RegisteredFreshTrialHistoryLedgerTestBridge::begin();
    RegisteredFreshTrialHistoryLedgerBridge::append_failed(
        ledger, std::move(failed_for_ledger));
    RegisteredFreshTrialHistoryLedgerBridge::append_complete(
        ledger, std::move(success_for_ledger));
    const auto ledger_summary =
        RegisteredFreshTrialHistoryLedgerTestBridge::consume(
            RegisteredFreshTrialHistoryLedgerBridge::seal(
                std::move(ledger)));
    const std::vector<std::string> expected_ledger_trials{
        std::string(LEDGER_FAILED_TRIAL),
        std::string(LEDGER_SUCCESS_TRIAL)};
    const std::vector<bool> expected_ledger_failures{true, false};
    assert(ledger_summary.capture_trial_ids == expected_ledger_trials &&
           ledger_summary.failed == expected_ledger_failures &&
           ledger_summary.ledger_identity != Digest{});

    constexpr std::string_view ABORTED_TRIAL =
        "99999999-9999-4999-8999-999999999999";
    auto aborted_trial = RegisteredTrialAttemptHistoryTestBridge::begin({
        .classification = static_cast<CaptureClassification>(1),
        .capture_trial_id = std::string(ABORTED_TRIAL),
        .trial_identity = trial_identity(ABORTED_TRIAL),
    });
    RegisteredTrialAttemptHistoryTestBridge::observe(
        aborted_trial,
        binding(1, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", 0x79),
        {}, 0, TestOnlyChildDisposition::ExitNonzero, 23);
    auto aborted_history =
        RegisteredTrialAttemptHistoryRecorder::seal_failed(
            std::move(aborted_trial));
    auto aborted_ledger =
        RegisteredFreshTrialHistoryLedgerTestBridge::begin();
    RegisteredFreshTrialHistoryLedgerBridge::append_failed(
        aborted_ledger, std::move(aborted_history));
    const auto aborted_summary =
        RegisteredFreshTrialHistoryLedgerTestBridge::consume_aborted(
            RegisteredFreshTrialHistoryLedgerBridge::seal_aborted(
                std::move(aborted_ledger)));
    assert(aborted_summary.capture_trial_ids.size() == 1 &&
           aborted_summary.capture_trial_ids[0] == ABORTED_TRIAL &&
           aborted_summary.failed.size() == 1 &&
           aborted_summary.failed[0]);

    auto empty_success_ledger =
        RegisteredFreshTrialHistoryLedgerTestBridge::begin();
    assert(refuses([&] {
        (void)RegisteredFreshTrialHistoryLedgerBridge::seal(
            std::move(empty_success_ledger));
    }));
    auto empty_aborted_ledger =
        RegisteredFreshTrialHistoryLedgerTestBridge::begin();
    assert(refuses([&] {
        (void)RegisteredFreshTrialHistoryLedgerBridge::seal_aborted(
            std::move(empty_aborted_ledger));
    }));

    constexpr std::string_view DUPLICATE_TRIAL =
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    auto duplicate_first = make_failed_history(
        DUPLICATE_TRIAL, "cccccccc-cccc-4ccc-8ccc-cccccccccccc", 0x81);
    auto duplicate_second = make_failed_history(
        DUPLICATE_TRIAL, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", 0x82);
    auto duplicate_ledger =
        RegisteredFreshTrialHistoryLedgerTestBridge::begin();
    RegisteredFreshTrialHistoryLedgerBridge::append_failed(
        duplicate_ledger, std::move(duplicate_first));
    assert(refuses([&] {
        RegisteredFreshTrialHistoryLedgerBridge::append_failed(
            duplicate_ledger, std::move(duplicate_second));
    }));

    auto older = make_failed_history(
        "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        "12121212-1212-4212-8212-121212121212", 0x83);
    auto newer = make_failed_history(
        "13131313-1313-4313-8313-131313131313",
        "14141414-1414-4414-8414-141414141414", 0x84);
    auto reordered_ledger =
        RegisteredFreshTrialHistoryLedgerTestBridge::begin();
    RegisteredFreshTrialHistoryLedgerBridge::append_failed(
        reordered_ledger, std::move(newer));
    assert(refuses([&] {
        RegisteredFreshTrialHistoryLedgerBridge::append_failed(
            reordered_ledger, std::move(older));
    }));

    assert(refuses([&] {
        (void)RegisteredTrialAttemptHistoryTestBridge::begin({
            .classification = static_cast<CaptureClassification>(1),
            .capture_trial_id = std::string(TRIAL),
            .trial_identity = id(0x11),
        });
    }));

    for (const auto fault : {
             TestOnlySealedC03Fault::RetainWritable,
             TestOnlySealedC03Fault::SubstituteInode}) {
        auto attacked = RegisteredTrialAttemptHistoryTestBridge::begin(trial);
        auto attacked_binding =
            binding(1, "5a205f38-b917-4acd-8305-54548d100bd0", 0x75);
        attacked_binding.sealed_c03_fault = fault;
        assert(refuses([&] {
            RegisteredTrialAttemptHistoryTestBridge::observe(
                attacked, attacked_binding, complete, complete.size(),
                TestOnlyChildDisposition::ExitZero, 0);
        }));
    }
}
