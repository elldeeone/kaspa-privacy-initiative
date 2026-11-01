#include "OT/OTTripleSetup.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace source = kpb_mp_spdz_p1_ondemand_ot;

namespace {

void need(bool value) {
    if (!value) throw std::runtime_error("P1-OnDemandOT-source-control");
}

bool contains(
        std::span<const unsigned char> value, std::string_view needle) {
    return std::search(
        value.begin(), value.end(), needle.begin(), needle.end()) !=
        value.end();
}

bool contains_pointer(
        std::span<const unsigned char> value, std::uintptr_t pointer) {
    std::array<unsigned char, sizeof(pointer)> little{};
    std::array<unsigned char, sizeof(pointer)> big{};
    for (std::size_t index = 0; index < little.size(); ++index) {
        little[index] = static_cast<unsigned char>(pointer >> (index * 8U));
        big[big.size() - index - 1] = little[index];
    }
    return std::search(value.begin(), value.end(),
                       little.begin(), little.end()) != value.end() ||
        std::search(value.begin(), value.end(),
                    big.begin(), big.end()) != value.end();
}

std::uint64_t read_u64(
        std::span<const unsigned char> value, std::size_t& cursor) {
    need(cursor <= value.size() && value.size() - cursor >= 8);
    std::uint64_t result{};
    for (unsigned index = 0; index < 8; ++index)
        result = (result << 8U) | value[cursor++];
    return result;
}

bool random_window_defined(std::span<const unsigned char> value) {
    static constexpr std::string_view domain =
        "KPI_P1_MP_SPDZ_PRNG_PRIVATE_STATE_V2\n";
    need(contains(value, domain));
    std::size_t cursor = domain.size() + 4U * 8U;
    const auto seed_size = read_u64(value, cursor);
    need(seed_size <= value.size() - cursor);
    cursor += seed_size;
    const auto state_size = read_u64(value, cursor);
    need(state_size <= value.size() - cursor);
    cursor += state_size;
    return read_u64(value, cursor) == 1;
}

} // namespace

int main() {
    need(source::SourceAccess::
        test_only_underreserve_refuses_without_growth());

    constexpr auto pointer_bits =
        static_cast<std::uintptr_t>(0x1122334455667788ULL);
    const auto* source_player = reinterpret_cast<const void*>(pointer_bits);

    OTTripleSetup setup;
    auto packed_setup = source::SourceAccess::test_only_fixture_setup(
        setup, source_player, 1);
    need(contains(
        packed_setup.view(),
        "KPI_P1_MP_SPDZ_OT_TRIPLE_SETUP_STATE_V2\n"));
    need(contains(
        packed_setup.view(), "KPI_P1_MP_SPDZ_PRNG_PRIVATE_STATE_V2\n"));
    need(contains(
        packed_setup.view(), "KPI_P1_MP_SPDZ_TIMER_PRIVATE_STATE_V1\n"));
    need(!contains_pointer(packed_setup.view(), pointer_bits));

    auto before = source::SourceAccess::test_only_prng_before();
    need(contains(
        before.view(), "KPI_P1_MP_SPDZ_PRNG_PRIVATE_STATE_V2\n"));
    need(contains(
        before.view(), "KPI_P1_MP_SPDZ_TIMER_PRIVATE_STATE_V1\n"));
    need(before.size() < packed_setup.size());
    need(!random_window_defined(before.view()));
    auto after = source::SourceAccess::test_only_prng_after(setup);
    need(random_window_defined(after.view()));
    need(after.size() > before.size());

    auto base = source::SourceAccess::test_only_seeded_base(setup, 0);
    auto seeded = source::SourceAccess::test_only_base(base);
    need(contains(
        seeded.view(), "KPI_P1_MP_SPDZ_BASE_OT_TRANSIENT_STATE_V2\n"));
    need(contains(
        seeded.view(), "KPI_P1_MP_SPDZ_PRNG_PRIVATE_STATE_V2\n"));
    need(!contains_pointer(seeded.view(), pointer_bits));
    std::vector<unsigned char> seeded_copy(
        seeded.view().begin(), seeded.view().end());

    base.extend_length();
    auto first_advance = source::SourceAccess::test_only_base(base);
    need(!std::equal(
        seeded_copy.begin(), seeded_copy.end(),
        first_advance.view().begin(), first_advance.view().end()));
    base.extend_length();
    auto second_advance = source::SourceAccess::test_only_base(base);
    need(!std::equal(
        first_advance.view().begin(), first_advance.view().end(),
        second_advance.view().begin(), second_advance.view().end()));

    auto repacked_setup = source::SourceAccess::test_only_setup(setup);
    need(repacked_setup.size() == packed_setup.size());
    need(!contains_pointer(repacked_setup.view(), pointer_bits));

    std::vector<unsigned char> scrubbed(4096, 0xa5);
    const auto* retained = scrubbed.data();
    const auto retained_size = scrubbed.size();
    source::detail::cleanse(scrubbed);
    need(scrubbed.empty());
    for (std::size_t index = 0; index < retained_size; ++index)
        need(retained[index] == 0);
    source::detail::cleanse(seeded_copy);
}
