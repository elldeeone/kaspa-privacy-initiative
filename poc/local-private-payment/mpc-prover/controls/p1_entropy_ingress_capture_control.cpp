#include "p1_entropy_ingress_capture.hpp"

#include "Tools/random.h"
#include <SimplestOT_C/common/randombytes.h>
#include <cryptoTools/Common/Defines.h>

#include <array>
#include <algorithm>
#include <cstring>
#include <memory>
#include <set>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace kpi::mpc::p1_private_state;

namespace {

struct Record final {
    EntropySource source{};
    std::uint64_t callsite_rva{};
    std::uint64_t object{};
    std::uint64_t thread{};
    std::uint64_t allocation{};
    std::uint64_t before{};
    std::uint64_t after{};
    std::vector<unsigned char> bytes;
    std::vector<unsigned char> encoded;
};

struct Shared final {
    std::vector<Record> records;
    bool fail{};
    unsigned unavailable{};
    unsigned terminals{};
};

class TestHook final : public EntropyStateHook {
    std::shared_ptr<Shared> shared_;

public:
    explicit TestHook(std::shared_ptr<Shared> shared)
        : EntropyStateHook(TestOnlyConstruction{}),
          shared_(std::move(shared)) {}

    bool record_entropy_ingress(
            const EntropyIngressView& value) noexcept override {
        try {
            Record record{
                .source = value.source,
                .callsite_rva = value.callsite_rva,
                .object = value.object_epoch,
                .thread = value.thread_epoch,
                .allocation = value.allocation_epoch,
                .before = value.counter_before,
                .after = value.counter_after,
                .bytes = std::vector<unsigned char>(
                    value.exact_entropy.begin(), value.exact_entropy.end()),
                .encoded = encode_entropy_ingress(value),
            };
            shared_->records.push_back(std::move(record));
            return !shared_->fail;
        } catch (...) {
            return false;
        }
    }

    bool entropy_capture_terminal_noexcept() noexcept override {
        ++shared_->terminals;
        return !shared_->fail;
    }

    void entropy_unavailable_noexcept(EntropySource) noexcept override {
        ++shared_->unavailable;
    }
};

void need(bool value) {
    if (!value) throw std::runtime_error("p1-entropy-control-refused");
}

std::vector<unsigned char> bytes(const osuCrypto::block& value) {
    std::vector<unsigned char> result(sizeof(value));
    std::memcpy(result.data(), &value, result.size());
    return result;
}

int valid() {
    auto shared = std::make_shared<Shared>();
    auto capture = EntropyIngressCapture::test_only_begin(
        std::make_unique<TestHook>(shared));

    PRNG mp_spdz;
    mp_spdz.ReSeed();
    const std::vector<unsigned char> mp_seed(
        mp_spdz.get_seed(), mp_spdz.get_seed() + SEED_SIZE);

    std::array<unsigned char, 32> simplest{};
    simplestot_randombytes(simplest.data(), simplest.size());

    const auto crypto_tools = osuCrypto::sysRandomSeed();
    const auto crypto_seed = bytes(crypto_tools);

    std::array<unsigned char, 32> threaded_simplest{};
    std::thread worker([&] {
        simplestot_randombytes(
            threaded_simplest.data(), threaded_simplest.size());
    });
    worker.join();

    need(std::move(capture).finish_noexcept());
    need(shared->unavailable == 0 && shared->terminals == 1 &&
         shared->records.size() == 4);
    const auto& a = shared->records[0];
    const auto& b = shared->records[1];
    const auto& c = shared->records[2];
    const auto& d = shared->records[3];
    need(a.source == EntropySource::MpSpdzPrngReseed &&
         b.source == EntropySource::SimplestOtRandomBytes &&
         c.source == EntropySource::CryptoToolsSystemSeed &&
         d.source == EntropySource::SimplestOtRandomBytes);
    need(a.bytes == mp_seed &&
         b.bytes == std::vector<unsigned char>(simplest.begin(), simplest.end()) &&
         c.bytes == crypto_seed &&
         d.bytes == std::vector<unsigned char>(
             threaded_simplest.begin(), threaded_simplest.end()));
    need(a.object == 1 && b.object == 2 && c.object == 3 && d.object == 4 &&
         a.allocation == 1 && b.allocation == 2 &&
         c.allocation == 3 && d.allocation == 4);
    need(a.callsite_rva != 0 && b.callsite_rva != 0 &&
         c.callsite_rva != 0 && d.callsite_rva != 0 &&
         std::set<std::uint64_t>{a.callsite_rva, b.callsite_rva,
                                 c.callsite_rva, d.callsite_rva}.size() == 4);
    need(a.thread == 1 && b.thread == 1 && c.thread == 1 && d.thread == 2);
    need(a.before == 0 && a.after == 1 && b.before == 0 && b.after == 1 &&
         c.before == 0 && c.after == 1 && d.before == 1 && d.after == 2);
    for (const auto& record : shared->records) {
        const auto domain = entropy_source_domain(record.source);
        need(!record.encoded.empty() &&
             std::search(
                 record.encoded.begin(), record.encoded.end(),
                 domain.begin(), domain.end()) != record.encoded.end() &&
             std::search(
                 record.encoded.begin(), record.encoded.end(),
                 record.bytes.begin(), record.bytes.end()) !=
                 record.encoded.end());
    }

    auto invalid = EntropyIngressView{
        .source = EntropySource::MpSpdzPrngReseed,
        .callsite_rva = 1,
        .object_epoch = 1,
        .thread_epoch = 1,
        .allocation_epoch = 1,
        .counter_before = 0,
        .counter_after = 2,
        .exact_entropy = mp_seed,
    };
    try {
        (void)encode_entropy_ingress(invalid);
        need(false);
    } catch (const std::runtime_error&) {}
    return 0;
}

[[noreturn]] void failed_hook() {
    auto shared = std::make_shared<Shared>();
    shared->fail = true;
    auto capture = EntropyIngressCapture::test_only_begin(
        std::make_unique<TestHook>(shared));
    (void)capture;
    PRNG value;
    value.ReSeed();
    std::abort();
}

[[noreturn]] void wrong_width() {
    auto shared = std::make_shared<Shared>();
    auto capture = EntropyIngressCapture::test_only_begin(
        std::make_unique<TestHook>(shared));
    (void)capture;
    std::array<unsigned char, 31> value{};
    simplestot_randombytes(value.data(), value.size());
    std::abort();
}

int abandoned() {
    auto shared = std::make_shared<Shared>();
    {
        auto capture = EntropyIngressCapture::test_only_begin(
            std::make_unique<TestHook>(shared));
        (void)capture;
    }
    need(shared->unavailable == 1);
    return 0;
}

int worker_first() {
    auto shared = std::make_shared<Shared>();
    auto capture = EntropyIngressCapture::test_only_begin(
        std::make_unique<TestHook>(shared));
    std::array<unsigned char, 32> worker_bytes{};
    std::thread worker([&] {
        simplestot_randombytes(worker_bytes.data(), worker_bytes.size());
    });
    worker.join();
    PRNG root;
    root.ReSeed();
    need(std::move(capture).finish_noexcept());
    need(shared->records.size() == 2 &&
         shared->records[0].thread == 2 &&
         shared->records[1].thread == 1);
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    const std::string mode(argv[1]);
    if (mode == "valid") return valid();
    if (mode == "failed-hook") failed_hook();
    if (mode == "wrong-width") wrong_width();
    if (mode == "abandoned") return abandoned();
    if (mode == "worker-first") return worker_first();
    return 2;
}
