#include "../../owner_input_ddnnt.hpp"

#include <array>
#include <cassert>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

using namespace kpi::mpc;

namespace {

void refuses(auto callable) {
    bool caught = false;
    try { callable(); }
    catch (const std::runtime_error&) { caught = true; }
    assert(caught);
}

void refuses_with(auto callable, const std::string& expected) {
    bool caught = false;
    try { callable(); }
    catch (const std::runtime_error& error) {
        caught = true;
        assert(error.what() == expected);
    }
    assert(caught);
}

std::array<std::vector<Fr>, 3> valid_party_frames() {
    // Public deterministic arithmetic control. Production values come only
    // from fresh authenticated MASCOT preprocessing.
    const std::array<std::array<Fr, DDNNT_COMPONENT_COUNT>, 2> totals{{
        {Fr(11), Fr(7), Fr(77), Fr(13), Fr(91)},
        {Fr(5), Fr(9), Fr(45), Fr(4), Fr(36)},
    }};
    std::array<std::vector<Fr>, 3> frames;
    for (const auto& tuple : totals) {
        for (std::size_t component = 0; component < tuple.size(); ++component) {
            frames[0].push_back(tuple[component]);
            frames[1].push_back(Fr(0));
            frames[2].push_back(Fr(0));
        }
    }
    return frames;
}

void both_equations_and_exact_masking_are_required() {
    const auto frames = valid_party_frames();
    const auto masks = reconstruct_checked_ddnnt_masks(frames, 2);
    assert(masks == std::vector<Fr>({Fr(11), Fr(5)}));

    const std::vector<Fr> values{Fr(101), Fr(202)};
    auto difference = make_owner_masked_difference_frame(values, masks);
    const auto decoded = decode_owner_fr_frame(difference, values.size());
    assert(difference.done());
    for (std::size_t index = 0; index < values.size(); ++index)
        assert(decoded[index] + masks[index] == values[index]);

    auto bad_w = frames;
    bad_w[1][DDNNT_W] += Fr(1);
    refuses([&] { (void) reconstruct_checked_ddnnt_masks(bad_w, 2); });

    auto bad_u = frames;
    bad_u[1][DDNNT_COMPONENT_COUNT + DDNNT_U] += Fr(1);
    refuses([&] { (void) reconstruct_checked_ddnnt_masks(bad_u, 2); });

    // Selective-failure attempt: alter r and make w consistent with a guess
    // s=11. The independent u=v*r equation still refuses the guessed case;
    // an incorrect s guess is refused by w=s*r as well.
    auto guessed_s = frames;
    guessed_s[1][DDNNT_R] += Fr(1);
    guessed_s[1][DDNNT_W] += Fr(11);
    refuses_with(
        [&] { (void) reconstruct_checked_ddnnt_masks(guessed_s, 2); },
        "owner-ddnnt-u-equals-v-times-r");

    auto wrong_s_guess = frames;
    wrong_s_guess[1][DDNNT_R] += Fr(1);
    wrong_s_guess[1][DDNNT_W] += Fr(12);
    refuses_with(
        [&] { (void) reconstruct_checked_ddnnt_masks(wrong_s_guess, 2); },
        "owner-ddnnt-w-equals-s-times-r");
}

void malformed_noncanonical_and_old_widths_refuse() {
    const auto frames = valid_party_frames();
    auto valid = pack_owner_fr_frame(frames[0]);
    assert(decode_owner_fr_frame(valid, 2 * DDNNT_COMPONENT_COUNT) ==
           frames[0]);

    auto old_three_n = pack_owner_fr_frame(
        std::span<const Fr>(frames[0]).first(2 * 3));
    refuses([&] {
        (void) decode_owner_fr_frame(old_three_n,
                                     2 * DDNNT_COMPONENT_COUNT);
    });
    std::vector<Fr> additive_only{Fr(1), Fr(2)};
    auto old_additive = pack_owner_fr_frame(additive_only);
    refuses([&] {
        (void) decode_owner_fr_frame(old_additive,
                                     2 * DDNNT_COMPONENT_COUNT);
    });

    auto truncated = pack_owner_fr_frame(frames[0]);
    truncated.rewind_write_head(1);
    refuses([&] {
        (void) decode_owner_fr_frame(truncated,
                                     2 * DDNNT_COMPONENT_COUNT);
    });

    std::array<unsigned char, 32> encoded{};
    bigint modulus(FR_MODULUS);
    std::size_t written = 0;
    mpz_export(encoded.data(), &written, -1, 1, 0, 0, modulus.get_mpz_t());
    assert(written == encoded.size());
    octetStream alias(encoded.size(), encoded.data());
    refuses([&] { (void) decode_owner_fr_frame(alias, 1); });
    refuses([&] {
        require_owner_fr_frame_length(
            alias, std::numeric_limits<std::size_t>::max());
    });
}

} // namespace

int main() {
    bigint::init_thread();
    Fr::init_field(bigint(FR_MODULUS));
    both_equations_and_exact_masking_are_required();
    malformed_noncanonical_and_old_widths_refuse();
}
