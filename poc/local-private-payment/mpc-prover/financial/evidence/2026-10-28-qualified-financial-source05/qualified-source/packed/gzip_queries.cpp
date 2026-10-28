#include "gzip_queries.hpp"
#include "point_codec.hpp"
#include <algorithm>
#include <future>
#include <limits>
#include <openssl/evp.h>

#if defined(INSECURE) || defined(NDEBUG) || defined(DEBUG_MAC) || defined(PRINT_MAC)
#error "Compressed public queries retain all canonical and subgroup checks"
#endif

namespace kpi::mpc::packed {
namespace {
[[noreturn]] void refuse(const char* code) { throw FormatError(code); }
uint64_t add(uint64_t a, uint64_t b) {
    if (a > std::numeric_limits<uint64_t>::max() - b) refuse("gzip-query-count-overflow");
    return a + b;
}
uint64_t mul(uint64_t a, uint64_t b) {
    if (b && a > std::numeric_limits<uint64_t>::max() / b) refuse("gzip-query-count-overflow");
    return a * b;
}
void hash_format(const std::string& value) {
    if (value.size() != 64 || value.find_first_not_of("0123456789abcdef") != std::string::npos)
        refuse("gzip-query-hash-format");
}
std::string hex(std::span<const unsigned char> bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result; result.reserve(bytes.size() * 2);
    for (auto b : bytes) { result += digits[b >> 4]; result += digits[b & 15]; }
    return result;
}
class Hash {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> hash_{EVP_MD_CTX_new(), EVP_MD_CTX_free};
public:
    Hash() {
        if (!hash_ || EVP_DigestInit_ex(hash_.get(), EVP_sha256(), nullptr) != 1)
            refuse("gzip-query-hash-init");
    }
    void bytes(std::span<const unsigned char> data) {
        if (EVP_DigestUpdate(hash_.get(), data.data(), data.size()) != 1) refuse("gzip-query-hash-update");
    }
    void text(const std::string& value) { bytes({reinterpret_cast<const unsigned char*>(value.data()), value.size()}); }
    void number(uint64_t value) {
        std::array<unsigned char, 8> encoded{};
        for (unsigned i = 0; i < 8; ++i) encoded[i] = static_cast<unsigned char>(value >> (8 * i));
        bytes(encoded);
    }
    std::string finish() {
        std::array<unsigned char, 32> digest{}; unsigned length = 0;
        if (EVP_DigestFinal_ex(hash_.get(), digest.data(), &length) != 1 || length != digest.size())
            refuse("gzip-query-hash-final");
        return hex(digest);
    }
};
uint64_t integer(std::span<const unsigned char> bytes) {
    if (bytes.size() != 8) refuse("gzip-query-count-width");
    uint64_t result = 0;
    for (unsigned i = 0; i < 8; ++i) result |= uint64_t(bytes[i]) << (8 * i);
    return result;
}
std::array<uint64_t, 5> counts(const StockQueryShape& shape) {
    const auto variables = add(shape.instances, shape.witnesses);
    if (!shape.instances || !shape.domain || (shape.domain & (shape.domain - 1)) ||
        shape.domain > (uint64_t{1} << 28)) refuse("gzip-query-stock-shape");
    return {variables, variables, variables, shape.domain - 1, shape.witnesses};
}
uint64_t vk_size(const StockQueryShape& shape) { return add(232, mul(shape.instances, 32)); }
uint64_t pk_size(const StockQueryShape& shape) {
    const auto n = add(shape.instances, shape.witnesses);
    (void) counts(shape);
    return add(add(add(add(vk_size(shape), 64 + 40), mul(n, 128)), mul(shape.domain - 1, 32)), mul(shape.witnesses, 32));
}
class Reader {
    std::unique_ptr<std::istream> input_;
    Hash hash_;
    uint64_t consumed_ = 0;
    const GzipQueryPins& pins_;
public:
    Reader(const SealedTraceArtifact& source, const GzipQueryPins& pins) : input_(source.stream()), pins_(pins) {}
    void read(std::span<unsigned char> bytes) {
        if (consumed_ > pins_.canonical_pk_bytes || bytes.size() > pins_.canonical_pk_bytes - consumed_)
            refuse("gzip-query-read-exceeds-stock-frame");
        if (bytes.size() > static_cast<size_t>(std::numeric_limits<std::streamsize>::max()))
            refuse("gzip-query-host-read-width");
        input_->read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (input_->gcount() != static_cast<std::streamsize>(bytes.size())) refuse("gzip-query-truncated");
        hash_.bytes(bytes); consumed_ = add(consumed_, bytes.size());
    }
    uint64_t count() { std::array<unsigned char, 8> value{}; read(value); return integer(value); }
    void finish() {
        // Reaching the canonical EOF also verifies the one-member gzip CRC,
        // trailer and absence of concatenated/trailing data in the sealed codec.
        const auto extra = input_->get();
        if (extra != std::char_traits<char>::eof() || !input_->eof() ||
            consumed_ != pins_.canonical_pk_bytes || hash_.finish() != pins_.canonical_pk_sha256)
            refuse("gzip-query-canonical-EOF-size-or-hash");
    }
};
constexpr std::array<uint64_t, 5> widths{32, 32, 64, 32, 32};
unsigned kind(Query query) {
    const auto value = static_cast<unsigned>(query);
    if (value >= widths.size()) refuse("gzip-query-kind");
    return value;
}
}  // namespace

namespace detail {
struct GzipQueries {
    const std::shared_ptr<const SealedTraceArtifact> artifact;
    const std::vector<unsigned char> vk;
    const StockQueryShape shape;
    const GzipQueryPins pins;
    const std::array<uint64_t, 5> lengths;
    std::vector<unsigned char> prefix;
    std::array<G1Value, 3> g1;
    std::array<G2Value, 3> g2;
    std::string identity;
    GzipQueries(std::shared_ptr<const SealedTraceArtifact> file, std::span<const unsigned char> value,
                const StockQueryShape& s, const GzipQueryPins& p)
        : artifact(std::move(file)), vk(value.begin(), value.end()), shape(s), pins(p), lengths(counts(s)) {}
};
struct GzipCursor {
    const std::shared_ptr<const GzipQueries> source;
    Reader input;
    unsigned section = 0;
    uint64_t at = 0;
    bool poisoned = false, finished = false;
    explicit GzipCursor(std::shared_ptr<const GzipQueries> state)
        : source(std::move(state)), input(*source->artifact, source->pins) {
        std::array<unsigned char, 65536> buffer{};
        for (size_t offset = 0; offset < source->prefix.size();) {
            const auto length = std::min(buffer.size(), source->prefix.size() - offset);
            input.read(std::span<unsigned char>(buffer.data(), length));
            if (!std::equal(buffer.begin(), buffer.begin() + length, source->prefix.begin() + offset))
                refuse("gzip-query-fixed-prefix-changed");
            offset += length;
        }
        enter();
    }
    void enter() {
        while (section < source->lengths.size()) {
            if (input.count() != source->lengths[section]) refuse("gzip-query-vector-count");
            at = 0;
            if (source->lengths[section]) return;
            ++section;
        }
    }
    std::array<unsigned char, 64> encoded(Query expected) {
        if (poisoned || finished) refuse("gzip-query-cursor-consumed-or-failed");
        const auto q = kind(expected);
        if (q != section || section >= source->lengths.size()) refuse("gzip-query-stock-order-or-count");
        std::array<unsigned char, 64> bytes{};
        input.read(std::span<unsigned char>(bytes.data(), static_cast<size_t>(widths[q])));
        if (++at == source->lengths[q]) { ++section; enter(); }
        return bytes;
    }
    void finish() {
        if (poisoned || finished) refuse("gzip-query-cursor-consumed-or-failed");
        if (section != source->lengths.size()) refuse("gzip-query-unconsumed-vector");
        input.finish(); finished = true;
    }
};
}  // namespace detail

GzipQueryCursor::GzipQueryCursor(std::shared_ptr<const detail::GzipQueries> source)
    : cursor_(std::make_unique<detail::GzipCursor>(std::move(source))) {}
GzipQueryCursor::GzipQueryCursor(GzipQueryCursor&&) noexcept = default;
GzipQueryCursor& GzipQueryCursor::operator=(GzipQueryCursor&&) noexcept = default;
GzipQueryCursor::~GzipQueryCursor() = default;
G1Value GzipQueryCursor::next_g1(Query expected) {
    if (!cursor_) refuse("gzip-query-moved-cursor");
    try {
        if (expected == Query::B2) refuse("gzip-query-group");
        const auto bytes = cursor_->encoded(expected);
        return admit_compressed_g1(std::span<const unsigned char>(bytes.data(), 32), CompressedPointRole::Query);
    } catch (...) { cursor_->poisoned = true; throw; }
}
G2Value GzipQueryCursor::next_g2() {
    if (!cursor_) refuse("gzip-query-moved-cursor");
    try { return admit_compressed_g2(cursor_->encoded(Query::B2), CompressedPointRole::Query); }
    catch (...) { cursor_->poisoned = true; throw; }
}
void GzipQueryCursor::finish() {
    if (!cursor_) refuse("gzip-query-moved-cursor");
    try { cursor_->finish(); } catch (...) { cursor_->poisoned = true; throw; }
}

GzipQueryStore::GzipQueryStore(std::shared_ptr<const detail::GzipQueries> value) : queries_(std::move(value)) {}
GzipQueryStore GzipQueryStore::admit(std::shared_ptr<const SealedTraceArtifact> artifact,
    std::span<const unsigned char> canonical_vk, const StockQueryShape& shape, const GzipQueryPins& pins) {
    initialize_bn254_field(); initialize_bn254_groups();
    for (const auto* value : {&pins.container_sha256, &pins.canonical_pk_sha256, &pins.decoder_identity, &pins.vk_sha256}) hash_format(*value);
    if (!artifact || !artifact->gzip() || artifact->container_bytes() != pins.container_bytes ||
        artifact->canonical_bytes() != pins.canonical_pk_bytes || artifact->container_sha256() != pins.container_sha256 ||
        artifact->canonical_sha256() != pins.canonical_pk_sha256 || artifact->decoder_identity() != pins.decoder_identity ||
        pins.canonical_pk_bytes != pk_size(shape) || canonical_vk.size() != vk_size(shape))
        refuse("gzip-query-artifact-pin-decoder-or-stock-size");
    auto source = std::make_shared<detail::GzipQueries>(std::move(artifact), canonical_vk, shape, pins);
    Hash vk_hash; vk_hash.bytes(source->vk);
    if (vk_hash.finish() != pins.vk_sha256 || integer(std::span<const unsigned char>(source->vk.data() + 224, 8)) != shape.instances)
        refuse("gzip-query-VK-pin-or-shape");
    source->g1[0] = admit_compressed_g1(std::span<const unsigned char>(source->vk.data(), 32), CompressedPointRole::Base);
    for (unsigned i = 0; i < 3; ++i)
        source->g2[i] = admit_compressed_g2(std::span<const unsigned char>(source->vk.data() + 32 + 64 * i, 64), CompressedPointRole::Base);
    for (uint64_t i = 0; i < shape.instances; ++i)
        (void) admit_compressed_g1(std::span<const unsigned char>(source->vk.data() + 232 + 32 * i, 32), CompressedPointRole::Base);
    Reader prefix(*source->artifact, source->pins);
    if (add(vk_size(shape), 64) > std::numeric_limits<size_t>::max()) refuse("gzip-query-host-prefix-width");
    source->prefix.resize(static_cast<size_t>(add(vk_size(shape), 64)));
    prefix.read(source->prefix);
    if (!std::equal(source->vk.begin(), source->vk.end(), source->prefix.begin())) refuse("gzip-query-PK-VK-prefix");
    source->g1[1] = admit_compressed_g1(std::span<const unsigned char>(source->prefix.data() + source->vk.size(), 32), CompressedPointRole::Base);
    source->g1[2] = admit_compressed_g1(std::span<const unsigned char>(source->prefix.data() + source->vk.size() + 32, 32), CompressedPointRole::Base);
    // Complete admission, with bounded PUBLIC byte chunks. Workers only admit
    // public compressed points; no secret arithmetic or unchecked constructor.
    detail::GzipCursor scan(source);
    constexpr size_t chunk_size = 4096, workers = 8;
    for (unsigned q = 0; q < source->lengths.size(); ++q) {
        for (uint64_t offset = 0; offset < source->lengths[q];) {
            const auto count = static_cast<size_t>(std::min<uint64_t>(chunk_size, source->lengths[q] - offset));
            std::vector<std::array<unsigned char, 64>> bytes; bytes.reserve(count);
            for (size_t i = 0; i < count; ++i) bytes.push_back(scan.encoded(static_cast<Query>(q)));
            std::vector<std::future<void>> work;
            for (size_t worker = 0; worker < std::min(workers, count); ++worker) {
                work.emplace_back(std::async(std::launch::async, [&, worker, q] {
                    for (size_t i = worker; i < bytes.size(); i += workers) {
                        if (q == static_cast<unsigned>(Query::B2)) (void) admit_compressed_g2(bytes[i], CompressedPointRole::Query);
                        else (void) admit_compressed_g1(std::span<const unsigned char>(bytes[i].data(), 32), CompressedPointRole::Query);
                    }
                }));
            }
            for (auto& result : work) result.get();
            offset += count;
        }
    }
    scan.finish();
    Hash identity; identity.text("KPI_GZIP_STOCK_PK_V1\n");
    for (const auto* value : {&pins.container_sha256, &pins.canonical_pk_sha256, &pins.vk_sha256, &pins.decoder_identity}) identity.text(*value);
    for (auto value : {pins.container_bytes, pins.canonical_pk_bytes, shape.instances, shape.witnesses, shape.domain}) identity.number(value);
    source->identity = identity.finish();
    return GzipQueryStore(std::move(source));
}
const StockQueryShape& GzipQueryStore::shape() const { return queries_->shape; }
const GzipQueryPins& GzipQueryStore::pins() const { return queries_->pins; }
const std::string& GzipQueryStore::transport_identity() const { return queries_->identity; }
uint64_t GzipQueryStore::query_size(Query query) const { return queries_->lengths[kind(query)]; }
G1Value GzipQueryStore::base_g1(BaseG1 role) const {
    switch (role) { case BaseG1::Alpha: return queries_->g1[0]; case BaseG1::Beta: return queries_->g1[1]; case BaseG1::Delta: return queries_->g1[2]; }
    refuse("gzip-query-base-role");
}
G2Value GzipQueryStore::base_g2(BaseG2 role) const {
    switch (role) { case BaseG2::Beta: return queries_->g2[0]; case BaseG2::Gamma: return queries_->g2[1]; case BaseG2::Delta: return queries_->g2[2]; }
    refuse("gzip-query-base-role");
}
GzipQueryCursor GzipQueryStore::cursor() const { return GzipQueryCursor(queries_); }
}  // namespace kpi::mpc::packed
