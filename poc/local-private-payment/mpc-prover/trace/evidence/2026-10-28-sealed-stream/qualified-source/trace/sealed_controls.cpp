// Public lossless-container controls; no field/MPC context is linked.
#include "sealed_trace.hpp"
#include <array>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <stdexcept>

namespace {
class Hash {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> value_{EVP_MD_CTX_new(), EVP_MD_CTX_free};
public:
    Hash() {
        if (!value_ || EVP_DigestInit_ex(value_.get(), EVP_sha256(), nullptr) != 1)
            throw std::runtime_error("public-sealed-hash-init");
    }
    void add(const char* bytes, size_t length) {
        if (EVP_DigestUpdate(value_.get(), bytes, length) != 1)
            throw std::runtime_error("public-sealed-hash-update");
    }
    std::string finish() {
        std::array<unsigned char, 32> bytes{}; unsigned length = 0;
        if (EVP_DigestFinal_ex(value_.get(), bytes.data(), &length) != 1 || length != bytes.size())
            throw std::runtime_error("public-sealed-hash-final");
        constexpr char digits[] = "0123456789abcdef";
        std::string result;
        for (auto byte : bytes) { result += digits[byte >> 4]; result += digits[byte & 15]; }
        return result;
    }
};
}

int main(int argc, char** argv) {
    try {
        if (argc != 6) throw std::runtime_error("public-sealed-control-arity");
        const auto artifact = kpi::mpc::SealedTraceArtifact::load(argv[1]);
        if (artifact->canonical_sha256() != argv[2]) throw std::runtime_error("public-sealed-canonical-pin");
        if (artifact->canonical_bytes() != std::stoull(argv[3])) throw std::runtime_error("public-sealed-byte-count");
        if (artifact->container_sha256() != argv[4]) throw std::runtime_error("public-sealed-container-pin");
        const std::string control(argv[5]);
        if (control == "replace-source") {
            std::ofstream changed(argv[1], std::ios::binary | std::ios::trunc);
            changed << "PUBLIC SOURCE REPLACED AFTER SEAL\n";
            if (!changed) throw std::runtime_error("public-sealed-source-mutation");
        } else if (control != "positive") throw std::runtime_error("public-sealed-control-name");
        auto first = artifact->stream(), second = artifact->stream();
        Hash one, two;
        size_t count_one = 0, count_two = 0;
        std::array<char, 65536> a{};
        std::array<char, 137> b{};
        while (*first || *second) {
            if (*first) {
                first->read(a.data(), a.size()); const auto n = static_cast<size_t>(first->gcount());
                one.add(a.data(), n); count_one += n;
            }
            // The second stream uses a different cursor and chunk size.
            if (*second) {
                second->read(b.data(), b.size()); const auto n = static_cast<size_t>(second->gcount());
                two.add(b.data(), n); count_two += n;
            }
        }
        if (!first->eof() || !second->eof() || count_one != artifact->canonical_bytes() ||
            count_two != count_one || one.finish() != artifact->canonical_sha256() ||
            two.finish() != artifact->canonical_sha256())
            throw std::runtime_error("public-sealed-independent-streams");
        std::cout << "PUBLIC_SEALED_TRACE_PASS " << artifact->canonical_bytes() << ' '
                  << artifact->container_bytes() << ' ' << (artifact->gzip() ? "gzip" : "plain")
                  << ' ' << artifact->decoder_identity() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cout << "PUBLIC_SEALED_TRACE_REFUSED " << error.what() << '\n';
        return 1;
    }
}
