#include "p1_beaver_source_capture.hpp"
#include "p1_scalar_capture_manifest.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

using namespace kpi::mpc;
using namespace kpi::mpc::p1_private_state;

namespace {

using Fr = gfp_<0, 4>;
using Auth = Share<Fr>;

constexpr const char* FR_MODULUS =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

void expect(bool condition) {
    if (!condition) throw std::runtime_error("p1-beaver-source-control");
}

void append_u64(std::vector<unsigned char>& output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        output.push_back(static_cast<unsigned char>(value >> shift));
}

template<class Value>
void append_native(std::vector<unsigned char>& output, const Value& value) {
    octetStream packed;
    value.pack(packed);
    append_u64(output, packed.get_length());
    output.insert(
        output.end(), packed.get_data(),
        packed.get_data() + packed.get_length());
}

void append_share(std::vector<unsigned char>& output, const Auth& value) {
    append_native(output, value.get_share());
    append_native(output, value.get_mac());
}

std::vector<unsigned char> with_domain(std::string_view domain) {
    return std::vector<unsigned char>(domain.begin(), domain.end());
}

Auth auth(long share, long mac) {
    return Auth(SemiShare<Fr>(Fr(share)), SemiShare<Fr>(Fr(mac)));
}

std::vector<unsigned char> triple_encoding(
        std::string_view domain, const std::array<Auth, 3>& triple) {
    auto output = with_domain(domain);
    for (const auto& value : triple) append_share(output, value);
    return output;
}

struct Record final {
    BeaverEventKind kind{};
    std::uint64_t item_index{};
    std::uint64_t cache_epoch{};
    std::vector<unsigned char> source_state;
};

class Hook final : public BeaverStateHook {
    bool record_beaver_event(const BeaverEventView& view) noexcept override {
        try {
            (void)encode_beaver_event(view);
            records.push_back({
                .kind = view.kind,
                .item_index = view.item_index,
                .cache_epoch = view.cache_epoch,
                .source_state = std::vector<unsigned char>(
                    view.source_state.begin(), view.source_state.end()),
            });
            return true;
        }
        catch (...) {
            return false;
        }
    }

    bool beaver_terminal_noexcept() noexcept override {
        ++terminal;
        return true;
    }

    void beaver_unavailable_noexcept() noexcept override {
        ++unavailable;
    }

public:
    Hook() : BeaverStateHook(TestOnlyConstruction{}) {}
    std::vector<Record> records;
    unsigned terminal{};
    unsigned unavailable{};
};

void expect_state(
        const Hook& hook, std::size_t index, BeaverEventKind kind,
        const std::vector<unsigned char>& expected) {
    expect(index < hook.records.size());
    expect(hook.records[index].kind == kind);
    expect(hook.records[index].source_state == expected);
}

void source_exactness() {
    const Auth left = auth(1, 101);
    const Auth right = auth(2, 102);
    const std::array<Auth, 3> triple_a{
        auth(3, 103), auth(4, 104), auth(12, 112)};
    const std::array<Auth, 3> triple_b{
        auth(5, 105), auth(6, 106), auth(30, 130)};
    const std::array<std::array<Auth, 3>, 2> generated{
        triple_a, triple_b};
    const Auth masked_left = auth(7, 107);
    const Auth masked_right = auth(8, 108);
    const std::array<Auth, 3> mutated_b{
        triple_b[0], triple_b[1], auth(55, 155)};
    const Auth result_b = mutated_b[2];
    const std::array<Auth, 3> mutated_a{
        triple_a[0], triple_a[1], auth(44, 144)};
    const Auth result_a = mutated_a[2];

    // Selected source callbacks are inert before a private source scope is
    // installed, including serialization work.
    expect(BeaverStateSourceBridge::prepare_mul<Auth>(
               reinterpret_cast<const void*>(1), left, right) ==
           BeaverRetainResult::NotRequired);

    Hook hook;
    auto scope = BeaverStateTestBridge::install(hook, 71, 101, 1, 3);
    int cache = 0;
    int first_beaver = 0;
    int second_beaver = 0;

    expect(BeaverStateTestBridge::round_begin(*scope, 1));
    expect(BeaverStateTestBridge::batch_begin(
        *scope, static_cast<std::uint64_t>(
            p1_capture::ScalarCaptureSite::FinancialAssignmentResidual), 1));
    expect(BeaverStateSourceBridge::init_mul<Auth>(&first_beaver) ==
           BeaverRetainResult::Retained);
    expect(BeaverStateSourceBridge::prepare_mul<Auth>(
               &first_beaver, left, right) == BeaverRetainResult::Retained);
    expect(BeaverStateSourceBridge::cache_batch_generated<Auth>(
               &cache, generated, 0, 2) == BeaverRetainResult::Retained);
    expect(BeaverStateSourceBridge::cache_triple_pop<Auth>(
               &cache, triple_b, 2, 1) == BeaverRetainResult::Retained);
    expect(BeaverStateSourceBridge::triple_and_masks<Auth>(
               &first_beaver, triple_b, masked_left, masked_right) ==
           BeaverRetainResult::Retained);
    expect(BeaverStateSourceBridge::opened_result<Auth>(
               &first_beaver, Fr(9), Fr(10), mutated_b, result_b) ==
           BeaverRetainResult::Retained);
    expect(BeaverStateSourceBridge::finalize_return<Auth>(
               &first_beaver, result_b) == BeaverRetainResult::Retained);
    expect(BeaverStateTestBridge::round_end(*scope, 1));

    expect(BeaverStateTestBridge::round_begin(*scope, 2));
    expect(BeaverStateTestBridge::batch_begin(
        *scope, static_cast<std::uint64_t>(
            p1_capture::ScalarCaptureSite::StreamedHProduct), 1));
    expect(BeaverStateSourceBridge::init_mul<Auth>(&second_beaver) ==
           BeaverRetainResult::Retained);
    expect(BeaverStateSourceBridge::prepare_mul<Auth>(
               &second_beaver, right, left) == BeaverRetainResult::Retained);
    expect(BeaverStateSourceBridge::cache_triple_pop<Auth>(
               &cache, triple_a, 1, 0) == BeaverRetainResult::Retained);
    expect(BeaverStateSourceBridge::triple_and_masks<Auth>(
               &second_beaver, triple_a, masked_right, masked_left) ==
           BeaverRetainResult::Retained);
    expect(BeaverStateSourceBridge::opened_result<Auth>(
               &second_beaver, Fr(10), Fr(9), mutated_a, result_a) ==
           BeaverRetainResult::Retained);
    expect(BeaverStateSourceBridge::finalize_return<Auth>(
               &second_beaver, result_a) == BeaverRetainResult::Retained);
    expect(BeaverStateTestBridge::round_end(*scope, 2));
    expect(BeaverStateTestBridge::finish(std::move(scope)));
    expect(hook.terminal == 1 && hook.unavailable == 0);
    expect(hook.records.size() == 22);

    auto prepare = with_domain("KPI_P1_BEAVER_MULTIPLICANDS_NATIVE_V1\n");
    append_share(prepare, left);
    append_share(prepare, right);
    expect_state(hook, 4, BeaverEventKind::Prepare, prepare);

    auto batch = with_domain("KPI_P1_BEAVER_CACHE_BATCH_NATIVE_V1\n");
    append_u64(batch, generated.size());
    for (const auto& triple : generated)
        for (const auto& value : triple) append_share(batch, value);
    expect_state(hook, 5, BeaverEventKind::CacheBatchGenerated, batch);

    const auto identity_b = triple_encoding(
        "KPI_P1_BEAVER_TRIPLE_IDENTITY_NATIVE_V1\n", triple_b);
    expect_state(hook, 6, BeaverEventKind::CacheTriplePop, identity_b);
    expect(hook.records[6].item_index == 0 &&
           hook.records[6].cache_epoch == 1);

    auto masks = with_domain(
        "KPI_P1_BEAVER_TRIPLE_AND_MASKS_NATIVE_V1\n");
    for (const auto& value : triple_b) append_share(masks, value);
    append_share(masks, masked_left);
    append_share(masks, masked_right);
    expect_state(hook, 7, BeaverEventKind::TripleMask, masks);

    auto opened = with_domain("KPI_P1_BEAVER_OPENED_RESULT_NATIVE_V1\n");
    append_native(opened, Fr(9));
    append_native(opened, Fr(10));
    for (const auto& value : mutated_b) append_share(opened, value);
    append_share(opened, result_b);
    expect_state(hook, 8, BeaverEventKind::OpenedResult, opened);

    auto returned = with_domain("KPI_P1_BEAVER_FINAL_RETURN_NATIVE_V1\n");
    append_share(returned, result_b);
    expect_state(hook, 9, BeaverEventKind::FinalizeReturn, returned);

    const auto identity_a = triple_encoding(
        "KPI_P1_BEAVER_TRIPLE_IDENTITY_NATIVE_V1\n", triple_a);
    expect_state(hook, 16, BeaverEventKind::CacheTriplePop, identity_a);

    int unselected_left = 1;
    int unselected_right = 2;
    expect(BeaverStateSourceBridge::prepare_mul<int>(
               &first_beaver, unselected_left, unselected_right) ==
           BeaverRetainResult::NotRequired);
}

void secret_temporary_wipes() {
    std::vector<unsigned char> value(4096, 0xa5);
    auto* retained = value.data();
    const auto size = value.size();
    beaver_source_detail::SecretBytes secret(std::move(value));
    secret.test_only_wipe();
    expect(secret.view().empty());
    for (std::size_t index = 0; index < size; ++index)
        expect(retained[index] == 0);
}

} // namespace

int main() {
    try {
        bigint::init_thread();
        Fr::init_field(bigint(FR_MODULUS));
        source_exactness();
        secret_temporary_wipes();
        return 0;
    }
    catch (...) {
        return 1;
    }
}
