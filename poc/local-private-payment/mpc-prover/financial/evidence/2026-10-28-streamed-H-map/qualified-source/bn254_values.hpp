#pragma once

// Thin value adapters for the stock MP-SPDZ authenticated-group MAC checks.
// Arithmetic is supplied by pinned mcl BN_SNARK1, not a new curve primitive.
#ifdef DEBUG_MAC
#error "DEBUG_MAC would expose private authentication material"
#endif
#include "auth_field.hpp"
#include "public_model.hpp"
#include <mcl/bn.hpp>
#include <array>
#include <algorithm>
#include <ostream>
#include <stdexcept>

namespace kpi::mpc {
inline constexpr const char* FQ_MODULUS =
    "21888242871839275222246405745257275088696311157297823662689037894645226208583";

void initialize_bn254_groups();
mcl::Fp parse_fq(const std::string& decimal);
std::array<unsigned char, 32> fq_bytes(const mcl::Fp& value);
mcl::Fp fq_from_bytes(std::span<const unsigned char, 32> encoded);
mcl::Fr mcl_scalar(const Fr& value);
bool fq_lexicographically_largest(const mcl::Fp& value);
bool fq2_lexicographically_largest(const mcl::Fp2& value);

template<class NativePoint, size_t Coefficients>
class Bn254Value : public ValueInterface {
    NativePoint point_;

    explicit Bn254Value(const NativePoint& point) : point_(point) {}

public:
    using Scalar = Fr;
    using next = Bn254Value;
    using Square = void;
    static const true_type invertible;
    static constexpr size_t coordinate_count = Coefficients;
    // Internal network encoding is one identity tag and explicit affine x/y.
    // It is deliberately independent of mcl stream/ETH compression modes.
    static constexpr size_t wire_size = 1 + 128 * Coefficients / 2;

    Bn254Value() { point_.clear(); }
    // Stock group MAC checks use implicit literal-zero comparisons/additions.
    // This constructor admits only the group identity, never a scalar value.
    Bn254Value(word zero) {
        if (zero != 0) throw std::invalid_argument("nonzero implicit group constant");
        point_.clear();
    }
    static int size() { return int(wire_size); }
    static int length() { return 254; }
    static std::string type_string() {
        return Coefficients == 1 ? "BN_SNARK1_G1" : "BN_SNARK1_G2";
    }
    static std::string type_short() { return Coefficients == 1 ? "K1" : "K2"; }
    static char type_char() { return Coefficients == 1 ? 'K' : 'L'; }
    static void specification(octetStream& os) {
        Scalar::specification(os);
        os.store_int(Coefficients, 1);
    }

    static Bn254Value admit(const AffinePoint& affine, bool allow_identity) {
        if (affine.x.size() != Coefficients || affine.y.size() != Coefficients)
            throw std::invalid_argument("group coordinate arity");
        if (affine.infinity) {
            if (!allow_identity) throw std::invalid_argument("group role forbids identity");
            if (!std::all_of(affine.x.begin(), affine.x.end(), [](const auto& x) { return x == "0"; }) ||
                !std::all_of(affine.y.begin(), affine.y.end(), [](const auto& y) { return y == "0"; }))
                throw std::invalid_argument("noncanonical group identity");
            return {};
        }
        typename NativePoint::Fp x, y;
        if constexpr (Coefficients == 1) {
            x = parse_fq(affine.x[0]);
            y = parse_fq(affine.y[0]);
        } else {
            x.a = parse_fq(affine.x[0]);
            x.b = parse_fq(affine.x[1]);
            y.a = parse_fq(affine.y[0]);
            y.b = parse_fq(affine.y[1]);
        }
        NativePoint point;
        bool valid = false;
        point.set(&valid, x, y);
        if (!valid || point.isZero() || !point.isValid() || !point.isValidOrder())
            throw std::invalid_argument("invalid or non-subgroup group point");
        return Bn254Value(point);
    }

    AffinePoint affine() const {
        check();
        AffinePoint out{point_.isZero(), std::vector<std::string>(Coefficients, "0"),
                        std::vector<std::string>(Coefficients, "0")};
        if (out.infinity) return out;
        auto point = point_;
        point.normalize();
        if constexpr (Coefficients == 1) {
            out.x[0] = point.x.getStr(10);
            out.y[0] = point.y.getStr(10);
        } else {
            out.x[0] = point.x.a.getStr(10);
            out.x[1] = point.x.b.getStr(10);
            out.y[0] = point.y.a.getStr(10);
            out.y[1] = point.y.b.getStr(10);
        }
        return out;
    }
    const NativePoint& point() const { return point_; }
    bool is_identity() const { return point_.isZero(); }
    void check() const {
        if (!point_.isValid() || !point_.isValidOrder())
            throw std::invalid_argument("group invariant");
    }

    Bn254Value operator+(const Bn254Value& other) const {
        NativePoint out;
        NativePoint::add(out, point_, other.point_);
        return Bn254Value(out);
    }
    Bn254Value operator-(const Bn254Value& other) const {
        NativePoint out;
        NativePoint::sub(out, point_, other.point_);
        return Bn254Value(out);
    }
    Bn254Value operator*(const Scalar& scalar) const {
        NativePoint out;
        NativePoint::mul(out, point_, mcl_scalar(scalar), true);
        return Bn254Value(out);
    }
    Bn254Value& operator+=(const Bn254Value& other) { return *this = *this + other; }
    Bn254Value& operator-=(const Bn254Value& other) { return *this = *this - other; }
    Bn254Value& operator*=(const Scalar& scalar) { return *this = *this * scalar; }
    bool operator==(const Bn254Value& other) const { return point_ == other.point_; }
    bool operator!=(const Bn254Value& other) const { return !(*this == other); }
    friend Bn254Value operator*(const Scalar& scalar, const Bn254Value& point) {
        return point * scalar;
    }

    std::array<unsigned char, wire_size> network_bytes() const {
        const auto coordinates = affine();
        std::array<unsigned char, wire_size> out{};
        if (coordinates.infinity) return out;
        out[0] = 1;
        for (size_t i = 0; i < Coefficients; ++i) {
            const auto x = fq_bytes(parse_fq(coordinates.x[i]));
            const auto y = fq_bytes(parse_fq(coordinates.y[i]));
            std::copy(x.begin(), x.end(), out.begin() + 1 + 32 * i);
            std::copy(y.begin(), y.end(), out.begin() + 1 + 32 * (Coefficients + i));
        }
        return out;
    }
    static Bn254Value from_network_bytes(std::span<const unsigned char> encoded) {
        if (encoded.size() != wire_size || encoded[0] > 1)
            throw std::invalid_argument("group network encoding");
        if (encoded[0] == 0) {
            if (!std::all_of(encoded.begin() + 1, encoded.end(), [](auto c) { return c == 0; }))
                throw std::invalid_argument("noncanonical network identity");
            return {};
        }
        AffinePoint affine{false, {}, {}};
        for (size_t i = 0; i < Coefficients; ++i) {
            affine.x.push_back(fq_from_bytes(std::span<const unsigned char, 32>(encoded.data() + 1 + 32 * i, 32)).getStr(10));
            affine.y.push_back(fq_from_bytes(std::span<const unsigned char, 32>(encoded.data() + 1 + 32 * (Coefficients + i), 32)).getStr(10));
        }
        // Peer-supplied opening/MAC elements get the same canonical, curve and
        // subgroup admission as public bases. Identity is lawful for shares.
        auto result = admit(affine, true);
        const auto canonical = result.network_bytes();
        if (!std::equal(canonical.begin(), canonical.end(), encoded.begin()))
            throw std::invalid_argument("group network roundtrip");
        return result;
    }
    void pack(octetStream& os, int = -1) const {
        const auto bytes = network_bytes();
        os.append(bytes.data(), bytes.size());
    }
    void unpack(octetStream& os, int = -1) {
        *this = from_network_bytes(std::span<const unsigned char>(os.consume(wire_size), wire_size));
    }
    // Generic debug printing could disclose an auxiliary opening or MAC share.
    // The completed proof has a separate, explicit final-output codec.
    void output(std::ostream&, bool) const {
        throw std::logic_error("group diagnostic output disabled");
    }
    friend std::ostream& operator<<(std::ostream& stream, const Bn254Value& point) {
        point.output(stream, true);
        return stream;
    }
};

using G1Value = Bn254Value<mcl::G1, 1>;
using G2Value = Bn254Value<mcl::G2, 2>;
}  // namespace kpi::mpc
