#include "packed_model.hpp"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <openssl/evp.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

#if defined(INSECURE) || defined(NDEBUG) || defined(DEBUG_MAC) || defined(PRINT_MAC)
#error "Packed public admission retains assertions and forbids insecure diagnostics"
#endif

namespace kpi::mpc::packed {
namespace {
[[noreturn]] void refuse(const char* code) { throw FormatError(code); }
uint64_t add(uint64_t a, uint64_t b) {
    if (a > std::numeric_limits<uint64_t>::max() - b) refuse("packed-count-overflow");
    return a + b;
}
uint64_t mul(uint64_t a, uint64_t b) {
    if (b && a > std::numeric_limits<uint64_t>::max() / b) refuse("packed-count-overflow");
    return a * b;
}
size_t host_size(uint64_t count) {
    if (count > std::numeric_limits<size_t>::max()) refuse("packed-host-size-overflow");
    return static_cast<size_t>(count);
}
void require_hash(const std::string& hash) {
    if (hash.size() != 64 || hash.find_first_not_of("0123456789abcdef") != std::string::npos)
        refuse("packed-hash-format");
}
std::string hex(std::span<const unsigned char> bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (auto byte : bytes) { out.push_back(digits[byte >> 4]); out.push_back(digits[byte & 15]); }
    return out;
}
class Hash {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> value_{EVP_MD_CTX_new(), EVP_MD_CTX_free};
    bool finalized_ = false;
public:
    Hash() {
        if (!value_ || EVP_DigestInit_ex(value_.get(), EVP_sha256(), nullptr) != 1)
            refuse("packed-hash-initialization");
    }
    void update(std::span<const unsigned char> bytes) {
        if (finalized_ || EVP_DigestUpdate(value_.get(), bytes.data(), bytes.size()) != 1)
            refuse("packed-hash-update");
    }
    void u64(uint64_t number) {
        std::array<unsigned char, 8> bytes{};
        for (unsigned i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<unsigned char>(number >> (8 * i));
        update(bytes);
    }
    std::string finish() {
        std::array<unsigned char, EVP_MAX_MD_SIZE> output{};
        unsigned length = 0;
        if (finalized_ || EVP_DigestFinal_ex(value_.get(), output.data(), &length) != 1 || length != 32)
            refuse("packed-hash-finalization");
        finalized_ = true;
        return hex({output.data(), length});
    }
};

std::array<unsigned char, 32> integer_bytes(const bigint& value) {
    if (value < 0 || mpz_sizeinbase(value.get_mpz_t(), 2) > 256) refuse("packed-integer-width");
    std::array<unsigned char, 32> bytes{};
    size_t written = 0;
    mpz_export(bytes.data(), &written, -1, 1, 0, 0, value.get_mpz_t());
    if (written > bytes.size()) refuse("packed-integer-width");
    return bytes;
}
Fr scalar(std::span<const unsigned char> bytes) {
    if (bytes.size() != 32) refuse("packed-Fr-width");
    bigint value;
    mpz_import(value.get_mpz_t(), bytes.size(), -1, 1, 0, 0, bytes.data());
    if (value < 0 || value >= fr_modulus()) refuse("packed-Fr-alias");
    return Fr(value);
}
uint64_t u64(std::span<const unsigned char> bytes) {
    if (bytes.size() != 8) refuse("packed-integer-width");
    uint64_t value = 0;
    for (unsigned i = 0; i < bytes.size(); ++i) value |= uint64_t(bytes[i]) << (8 * i);
    return value;
}

bool same_stat(const struct stat& a, const struct stat& b) {
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_size == b.st_size &&
        a.st_mtim.tv_sec == b.st_mtim.tv_sec && a.st_mtim.tv_nsec == b.st_mtim.tv_nsec &&
        a.st_ctim.tv_sec == b.st_ctim.tv_sec && a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
}
class MappedFile {
    int fd_ = -1;
    const unsigned char* data_ = nullptr;
    size_t size_ = 0;
    struct stat stat_{};
public:
    explicit MappedFile(const std::filesystem::path& path) {
        fd_ = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd_ == -1) refuse("packed-public-file-open");
        try {
            if (fstat(fd_, &stat_) != 0 || !S_ISREG(stat_.st_mode) || stat_.st_size <= 0)
                refuse("packed-public-file-type");
            if ((fcntl(fd_, F_GETFL) & O_ACCMODE) != O_RDONLY) refuse("packed-public-file-access");
            size_ = host_size(static_cast<uint64_t>(stat_.st_size));
            auto* address = mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd_, 0);
            if (address == MAP_FAILED) refuse("packed-public-map");
            data_ = static_cast<const unsigned char*>(address);
        } catch (...) { close(fd_); fd_ = -1; throw; }
    }
    ~MappedFile() {
        if (data_) munmap(const_cast<unsigned char*>(data_), size_);
        if (fd_ != -1) close(fd_);
    }
    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;
    size_t size() const { return size_; }
    std::span<const unsigned char> slice(uint64_t offset, uint64_t count) const {
        if (offset > size_ || count > size_ - offset) refuse("packed-public-slice-range");
        return {data_ + host_size(offset), host_size(count)};
    }
    void unchanged() const {
        struct stat current{};
        if (fstat(fd_, &current) != 0 || !same_stat(stat_, current)) refuse("packed-backing-changed");
    }
    std::string digest() const {
        Hash hash;
        for (size_t at = 0; at < size_;) {
            const auto count = std::min(size_t{65536}, size_ - at);
            hash.update(slice(at, count)); at += count;
        }
        unchanged();
        return hash.finish();
    }
};
struct Reader {
    const MappedFile& file;
    uint64_t position = 0;
    std::span<const unsigned char> take(uint64_t count) {
        auto result = file.slice(position, count);
        position = add(position, count);
        return result;
    }
    uint64_t count() { return u64(take(8)); }
    std::string hash() { return hex(take(32)); }
    Fr field() { return scalar(take(32)); }
};

Metadata parse_metadata(const MappedFile& file) {
    Reader reader{file};
    constexpr std::array<unsigned char, 16> magic{'K','P','I','_','P','A','C','K','E','D','_','V','1',0,0,0};
    const auto actual_magic = reader.take(magic.size());
    if (!std::equal(magic.begin(), magic.end(), actual_magic.begin())) refuse("packed-metadata-magic");
    const auto mode = reader.count();
    if (mode != 1 && mode != 2) refuse("packed-prefix-policy");
    const auto prime = integer_bytes(fr_modulus());
    const auto base = integer_bytes(bigint(std::string(FQ_MODULUS)));
    const auto actual_prime = reader.take(32), actual_base = reader.take(32);
    if (!std::equal(prime.begin(), prime.end(), actual_prime.begin()) ||
        !std::equal(base.begin(), base.end(), actual_base.begin())) refuse("packed-field-or-curve");
    Metadata meta{};
    meta.prefix_mode = static_cast<PrefixMode>(mode);
    meta.source_sha256 = reader.hash(); meta.original_model_sha256 = reader.hash();
    meta.pk_sha256 = reader.hash(); meta.vk_sha256 = reader.hash(); meta.matrix_fingerprint = reader.hash();
    for (auto& hash : meta.compressed_sha256) hash = reader.hash();
    for (auto& hash : meta.raw_sha256) hash = reader.hash();
    meta.instances = reader.count(); meta.witnesses = reader.count();
    meta.constraints = reader.count(); meta.domain = reader.count();
    meta.pk_bytes = reader.count(); meta.vk_bytes = reader.count();
    for (auto& count : meta.compressed_bytes) count = reader.count();
    for (auto& count : meta.raw_bytes) count = reader.count();
    meta.omega = reader.field(); meta.omega_inverse = reader.field();
    meta.inv_n = reader.field(); meta.coset_shift = reader.field();
    const auto instances = reader.count();
    if (!meta.instances || !meta.constraints || !meta.domain || meta.domain > (uint64_t{1} << 28) ||
        (meta.domain & (meta.domain - 1)) != 0 || add(meta.constraints, meta.instances) > meta.domain)
        refuse("packed-model-shape");
    (void) host_size(add(meta.instances, meta.witnesses));
    const std::string zero_hash(64, '0');
    if (mode == 1) {
        if (instances != meta.instances || meta.original_model_sha256 == zero_hash)
            refuse("packed-public-prefix-arity");
        for (uint64_t i = 0; i < instances; ++i) meta.public_prefix.push_back(reader.field());
        if (meta.public_prefix[0] != Fr(1)) refuse("packed-public-prefix-ONE");
    } else {
        if (instances != 0 || meta.original_model_sha256 != zero_hash)
            refuse("packed-derived-prefix-placeholders");
        meta.derived_output_count = reader.count();
        meta.prefix_recipe_sha256 = reader.hash(); meta.prefix_layout_sha256 = reader.hash();
        if (meta.derived_output_count != meta.instances - 1 ||
            meta.prefix_recipe_sha256 == zero_hash || meta.prefix_layout_sha256 == zero_hash)
            refuse("packed-derived-prefix-recipe");
    }
    if (reader.position != file.size()) refuse("packed-metadata-trailing");
    const bigint n(std::to_string(meta.domain));
    if (pow_public(meta.omega, n) != Fr(1) ||
        (meta.domain > 1 && pow_public(meta.omega, bigint(std::to_string(meta.domain / 2))) == Fr(1)) ||
        meta.omega * meta.omega_inverse != Fr(1) || Fr(n) * meta.inv_n != Fr(1) ||
        meta.coset_shift == Fr(0) || pow_public(meta.coset_shift, n) == Fr(1))
        refuse("packed-domain-roots");
    return meta;
}

class Inflate {
    const MappedFile& input_;
    z_stream stream_{};
    size_t supplied_ = 0;
    bool ended_ = false;
    Hash hash_;
    uint64_t raw_bytes_ = 0;
    bool step(std::span<unsigned char> output, size_t& written) {
        if (ended_) { written = 0; return false; }
        stream_.next_out = output.data();
        stream_.avail_out = static_cast<uInt>(output.size());
        while (stream_.avail_out) {
            if (stream_.avail_in == 0 && supplied_ < input_.size()) {
                const auto count = std::min(size_t{65536}, input_.size() - supplied_);
                const auto block = input_.slice(supplied_, count);
                stream_.next_in = const_cast<unsigned char*>(block.data());
                stream_.avail_in = static_cast<uInt>(count); supplied_ += count;
            }
            const auto before_in = stream_.avail_in, before_out = stream_.avail_out;
            const int status = inflate(&stream_, Z_NO_FLUSH);
            if (status == Z_STREAM_END) {
                ended_ = true;
                if (stream_.avail_in != 0 || supplied_ != input_.size()) refuse("packed-gzip-trailing-or-members");
                break;
            }
            if (status != Z_OK || (stream_.avail_in == before_in && stream_.avail_out == before_out))
                refuse("packed-gzip-truncated-or-invalid");
        }
        written = output.size() - stream_.avail_out;
        hash_.update({output.data(), written}); raw_bytes_ = add(raw_bytes_, written);
        return written != 0;
    }
public:
    explicit Inflate(const MappedFile& input) : input_(input) {
        if (input.size() < 2 || input.slice(0, 2)[0] != 0x1f || input.slice(0, 2)[1] != 0x8b)
            refuse("packed-gzip-magic");
        if (inflateInit2(&stream_, 15 + 16) != Z_OK) refuse("packed-gzip-initialization");
    }
    ~Inflate() { inflateEnd(&stream_); }
    void read(std::span<unsigned char> output) {
        if (output.size() > std::numeric_limits<uInt>::max()) refuse("packed-gzip-read-size");
        size_t written = 0;
        (void) step(output, written);
        if (written != output.size()) refuse("packed-raw-truncated");
    }
    uint64_t count() { std::array<unsigned char, 8> bytes{}; read(bytes); return u64(bytes); }
    uint64_t consumed() const { return raw_bytes_; }
    void finish(uint64_t expected_bytes, const std::string& expected_hash) {
        std::array<unsigned char, 1> extra{};
        size_t written = 0;
        if (step(extra, written)) refuse("packed-raw-trailing");
        if (!ended_ || raw_bytes_ != expected_bytes || hash_.finish() != expected_hash)
            refuse("packed-raw-size-or-digest");
        input_.unchanged();
    }
};

std::array<unsigned char, 32> encode_g1(const G1Value& point) {
    point.check();
    std::array<unsigned char, 32> bytes{};
    if (point.is_identity()) { bytes.back() = 0x40; return bytes; }
    auto value = point.point(); value.normalize(); bytes = fq_bytes(value.x);
    if (fq_lexicographically_largest(value.y)) bytes.back() |= 0x80;
    return bytes;
}
std::array<unsigned char, 64> encode_g2(const G2Value& point) {
    point.check();
    std::array<unsigned char, 64> bytes{};
    if (point.is_identity()) { bytes.back() = 0x40; return bytes; }
    auto value = point.point(); value.normalize();
    const auto a = fq_bytes(value.x.a), b = fq_bytes(value.x.b);
    std::copy(a.begin(), a.end(), bytes.begin()); std::copy(b.begin(), b.end(), bytes.begin() + 32);
    if (fq2_lexicographically_largest(value.y)) bytes.back() |= 0x80;
    return bytes;
}
template<size_t N> bool infinity(std::span<const unsigned char> bytes, bool allowed) {
    if (bytes.size() != N) refuse("packed-point-width");
    if (!(bytes.back() & 0x40)) return false;
    if (!allowed || bytes.back() != 0x40 ||
        !std::all_of(bytes.begin(), bytes.end() - 1, [](auto byte) { return byte == 0; }))
        refuse("packed-point-infinity");
    return true;
}
G1Value decode_g1(std::span<const unsigned char> bytes, bool allowed) {
    if (infinity<32>(bytes, allowed)) return {};
    std::array<unsigned char, 32> x_bytes{};
    std::copy(bytes.begin(), bytes.end(), x_bytes.begin());
    const bool largest = (x_bytes.back() & 0x80) != 0; x_bytes.back() &= 0x3f;
    const auto x = fq_from_bytes(x_bytes);
    mcl::Fp rhs, y; mcl::G1::getWeierstrass(rhs, x);
    if (!mcl::Fp::squareRoot(y, rhs)) refuse("packed-G1-nonsquare");
    if (fq_lexicographically_largest(y) != largest) y = -y;
    const auto point = G1Value::admit({false, {x.getStr(10)}, {y.getStr(10)}}, false);
    const auto canonical = encode_g1(point);
    if (!std::equal(canonical.begin(), canonical.end(), bytes.begin())) refuse("packed-G1-roundtrip");
    return point;
}
G2Value decode_g2(std::span<const unsigned char> bytes, bool allowed) {
    if (infinity<64>(bytes, allowed)) return {};
    std::array<unsigned char, 64> x_bytes{};
    std::copy(bytes.begin(), bytes.end(), x_bytes.begin());
    const bool largest = (x_bytes.back() & 0x80) != 0; x_bytes.back() &= 0x3f;
    mcl::Fp2 x, rhs, y;
    x.a = fq_from_bytes(std::span<const unsigned char, 32>(x_bytes.data(), 32));
    x.b = fq_from_bytes(std::span<const unsigned char, 32>(x_bytes.data() + 32, 32));
    mcl::G2::getWeierstrass(rhs, x);
    if (!mcl::Fp2::squareRoot(y, rhs)) refuse("packed-G2-nonsquare");
    if (fq2_lexicographically_largest(y) != largest) y = -y;
    const auto point = G2Value::admit({false, {x.a.getStr(10), x.b.getStr(10)},
        {y.a.getStr(10), y.b.getStr(10)}}, false);
    const auto canonical = encode_g2(point);
    if (!std::equal(canonical.begin(), canonical.end(), bytes.begin())) refuse("packed-G2-roundtrip");
    return point;
}
}  // namespace

namespace detail {
struct Section { uint64_t offset = 0, count = 0, width = 0; };
struct Storage {
    const MappedFile metadata_file;
    const Metadata meta;
    const std::string identity;
    const std::array<std::unique_ptr<MappedFile>, 3> matrices;
    const MappedFile pk, vk;
    std::array<Section, 5> queries{};
    uint64_t beta1 = 0, delta1 = 0;
    AdmissionStats stats;
    Storage(const std::filesystem::path& directory, const std::filesystem::path& pk_path,
            const std::filesystem::path& vk_path, const std::string& expected)
        : metadata_file(directory / "model.meta"), meta(parse_metadata(metadata_file)),
          identity(metadata_file.digest()),
          matrices{std::make_unique<MappedFile>(directory / "A.rows.gz"),
                   std::make_unique<MappedFile>(directory / "B.rows.gz"),
                   std::make_unique<MappedFile>(directory / "C.rows.gz")}, pk(pk_path), vk(vk_path) {
        if (identity != expected) refuse("packed-metadata-pin");
        stats.mapped_public_bytes = add(add(metadata_file.size(), pk.size()), vk.size());
        for (unsigned axis = 0; axis < 3; ++axis) {
            if (matrices[axis]->size() != meta.compressed_bytes[axis] ||
                matrices[axis]->digest() != meta.compressed_sha256[axis]) refuse("packed-axis-pin-or-size");
            stats.mapped_public_bytes = add(stats.mapped_public_bytes, matrices[axis]->size());
        }
        if (pk.size() != meta.pk_bytes || vk.size() != meta.vk_bytes ||
            pk.digest() != meta.pk_sha256 || vk.digest() != meta.vk_sha256) refuse("packed-key-pin-or-size");
        const auto vk_size = add(232, mul(meta.instances, 32));
        if (vk_size != vk.size() || u64(pk.slice(224, 8)) != meta.instances ||
            !std::equal(vk.slice(0, vk.size()).begin(), vk.slice(0, vk.size()).end(), pk.slice(0, vk.size()).begin()))
            refuse("packed-VK-prefix-or-shape");
        beta1 = vk_size; delta1 = add(beta1, 32);
        Reader reader{pk, add(vk_size, 64)};
        const auto variables = add(meta.instances, meta.witnesses);
        const std::array<uint64_t, 5> counts{variables, variables, variables, meta.domain - 1, meta.witnesses};
        const std::array<uint64_t, 5> widths{32, 32, 64, 32, 32};
        for (unsigned q = 0; q < queries.size(); ++q) {
            if (reader.count() != counts[q]) refuse("packed-query-arity");
            queries[q] = {reader.position, counts[q], widths[q]};
            (void) reader.take(mul(counts[q], widths[q]));
        }
        if (reader.position != pk.size()) refuse("packed-PK-trailing");
    }
    void unchanged() const {
        metadata_file.unchanged(); pk.unchanged(); vk.unchanged();
        for (const auto& file : matrices) file->unchanged();
    }
    std::span<const unsigned char> query(Query query, uint64_t index) const {
        const auto number = static_cast<unsigned>(query);
        if (number >= queries.size()) refuse("packed-query-kind");
        const auto& section = queries[number];
        if (index >= section.count) refuse("packed-query-index");
        return pk.slice(add(section.offset, mul(index, section.width)), section.width);
    }
};

struct Cursor {
    const std::shared_ptr<const Storage> storage;
    const unsigned axis;
    Inflate input;
    uint64_t row = 0;
    bool finished = false;
    Cursor(std::shared_ptr<const Storage> source, unsigned number)
        : storage(std::move(source)), axis(number), input(*storage->matrices.at(axis)) {
        storage->matrices[axis]->unchanged();
        std::array<unsigned char, 16> magic{}; input.read(magic);
        constexpr std::string_view expected = "KPI_R1CS_AXIS_V1";
        if (!std::equal(magic.begin(), magic.end(), expected.begin()) || input.count() != axis)
            refuse("packed-axis-header");
        std::array<unsigned char, 32> prime{}; input.read(prime);
        if (prime != integer_bytes(fr_modulus()) || input.count() != storage->meta.instances ||
            input.count() != storage->meta.witnesses || input.count() != storage->meta.constraints)
            refuse("packed-axis-field-or-shape");
    }
    bool next(SparseRow& output, Hash* fingerprint = nullptr) {
        if (finished) return false;
        if (row == storage->meta.constraints) {
            input.finish(storage->meta.raw_bytes[axis], storage->meta.raw_sha256[axis]);
            finished = true; output.clear(); return false;
        }
        const auto terms = input.count();
        if (fingerprint) fingerprint->u64(terms);
        if (input.consumed() > storage->meta.raw_bytes[axis] ||
            terms > (storage->meta.raw_bytes[axis] - input.consumed()) / 40)
            refuse("packed-row-exceeds-frame");
        if (terms > output.max_size()) refuse("packed-row-size");
        output.clear(); output.reserve(host_size(terms));
        const auto variables = add(storage->meta.instances, storage->meta.witnesses);
        for (uint64_t term = 0; term < terms; ++term) {
            std::array<unsigned char, 32> canonical{}; input.read(canonical);
            const auto index = input.count();
            if (index >= variables) refuse("packed-matrix-column-range");
            const auto coefficient = scalar(canonical);
            output.push_back({host_size(index), coefficient});
            if (fingerprint) { fingerprint->update(canonical); fingerprint->u64(index); }
        }
        ++row;
        return true;
    }
};
}  // namespace detail

RowCursor::RowCursor(std::shared_ptr<const detail::Storage> source, unsigned axis)
    : cursor_(std::make_unique<detail::Cursor>(std::move(source), axis)) {}
RowCursor::RowCursor(RowCursor&&) noexcept = default;
RowCursor& RowCursor::operator=(RowCursor&&) noexcept = default;
RowCursor::~RowCursor() = default;
bool RowCursor::next(SparseRow& row) {
    if (!cursor_) refuse("packed-moved-row-cursor");
    return cursor_->next(row);
}

PackedModel::PackedModel(std::shared_ptr<const detail::Storage> source) : storage_(std::move(source)) {}
PackedModel PackedModel::admit(const std::filesystem::path& directory,
    const std::filesystem::path& pk, const std::filesystem::path& vk, const std::string& expected) {
    require_hash(expected); initialize_bn254_field(); initialize_bn254_groups();
    auto source = std::make_shared<detail::Storage>(directory, pk, vk, expected);
    Hash fingerprint;
    constexpr std::array<unsigned char, 15> domain{'K','P','I','N','A','S','/','R','1','C','S','/','v','1',0};
    fingerprint.update(domain);
    fingerprint.u64(source->meta.instances); fingerprint.u64(source->meta.witnesses);
    fingerprint.u64(source->meta.constraints);
    for (unsigned axis = 0; axis < 3; ++axis) {
        detail::Cursor cursor(source, axis);
        SparseRow row;
        while (cursor.next(row, &fingerprint)) {
            source->stats.matrix_rows = add(source->stats.matrix_rows, 1);
            source->stats.matrix_terms = add(source->stats.matrix_terms, row.size());
            source->stats.maximum_row_terms = std::max(source->stats.maximum_row_terms, uint64_t(row.size()));
        }
    }
    if (fingerprint.finish() != source->meta.matrix_fingerprint) refuse("packed-matrix-fingerprint");
    const auto g1 = [&](std::span<const unsigned char> bytes, bool allow) {
        (void) decode_g1(bytes, allow); ++source->stats.g1_points;
    };
    const auto g2 = [&](std::span<const unsigned char> bytes, bool allow) {
        (void) decode_g2(bytes, allow); ++source->stats.g2_points;
    };
    g1(source->pk.slice(0, 32), false);
    for (auto offset : {uint64_t{32}, uint64_t{96}, uint64_t{160}}) g2(source->pk.slice(offset, 64), false);
    for (uint64_t i = 0; i < source->meta.instances; ++i) g1(source->pk.slice(add(232, mul(i, 32)), 32), false);
    g1(source->pk.slice(source->beta1, 32), false); g1(source->pk.slice(source->delta1, 32), false);
    for (unsigned q = 0; q < source->queries.size(); ++q)
        for (uint64_t index = 0; index < source->queries[q].count; ++index) {
            const auto bytes = source->query(static_cast<Query>(q), index);
            if (q == static_cast<unsigned>(Query::B2)) g2(bytes, true); else g1(bytes, true);
        }
    source->unchanged();
    return PackedModel(std::move(source));
}
const Metadata& PackedModel::metadata() const { return storage_->meta; }
const AdmissionStats& PackedModel::admission_stats() const { return storage_->stats; }
const std::string& PackedModel::identity() const { return storage_->identity; }
RowCursor PackedModel::rows(unsigned axis) const {
    if (axis > 2) refuse("packed-axis-range");
    return RowCursor(storage_, axis);
}
G1Value PackedModel::base_g1(BaseG1 role) const {
    uint64_t offset;
    switch (role) {
        case BaseG1::Alpha: offset = 0; break;
        case BaseG1::Beta: offset = storage_->beta1; break;
        case BaseG1::Delta: offset = storage_->delta1; break;
        default: refuse("packed-base-role");
    }
    return decode_g1(storage_->pk.slice(offset, 32), false);
}
G2Value PackedModel::base_g2(BaseG2 role) const {
    uint64_t offset;
    switch (role) {
        case BaseG2::Beta: offset = 32; break;
        case BaseG2::Gamma: offset = 96; break;
        case BaseG2::Delta: offset = 160; break;
        default: refuse("packed-base-role");
    }
    return decode_g2(storage_->pk.slice(offset, 64), false);
}
G1Value PackedModel::vk_gamma_abc(uint64_t index) const {
    if (index >= metadata().instances) refuse("packed-VK-index");
    return decode_g1(storage_->pk.slice(add(232, mul(index, 32)), 32), false);
}
uint64_t PackedModel::query_size(Query query) const {
    const auto kind = static_cast<unsigned>(query);
    if (kind >= storage_->queries.size()) refuse("packed-query-kind");
    return storage_->queries[kind].count;
}
G1Value PackedModel::g1_query(Query query, uint64_t index) const {
    if (query == Query::B2) refuse("packed-query-group");
    return decode_g1(storage_->query(query, index), true);
}
G2Value PackedModel::g2_query(uint64_t index) const {
    return decode_g2(storage_->query(Query::B2, index), true);
}
void PackedModel::check_backing_unchanged() const { storage_->unchanged(); }
}  // namespace kpi::mpc::packed
