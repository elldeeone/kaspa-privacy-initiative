#pragma once
#include "auth_field.hpp"
#include <array>

namespace kpi::mpc {
// Only a canonical public coin contribution is serialized. Stock Create_Random
// supplies its commitment/opening exchange and Fr supplies rejection sampling.
class CheckedFrContribution {
    Fr value_{0};
public:
    void randomize(PRNG& generator) { value_.randomize(generator); }
    void assign_zero() { value_ = Fr(0); }
    CheckedFrContribution& operator+=(const CheckedFrContribution& other) {
        value_ += other.value_; return *this;
    }
    void pack(octetStream& output) const {
        bigint canonical;
        to_bigint(canonical, value_);
        std::array<unsigned char, 32> bytes{};
        size_t written = 0;
        mpz_export(bytes.data(), &written, -1, 1, 0, 0, canonical.get_mpz_t());
        if (written > bytes.size()) throw std::runtime_error("coin-contribution-length");
        output.append(bytes.data(), bytes.size());
    }
    void unpack(octetStream& input) {
        if (input.get_length() != 32 || input.left() != 32)
            throw std::runtime_error("coin-contribution-frame");
        bigint canonical;
        mpz_import(canonical.get_mpz_t(), 32, -1, 1, 0, 0, input.consume(32));
        if (canonical < 0 || canonical >= fr_modulus() || !input.done())
            throw std::runtime_error("coin-contribution-noncanonical");
        value_ = Fr(canonical);
    }
    const Fr& public_value() const { return value_; }
};
}  // namespace kpi::mpc
