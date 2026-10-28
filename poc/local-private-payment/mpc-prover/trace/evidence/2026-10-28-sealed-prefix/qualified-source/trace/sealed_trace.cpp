#include "sealed_trace.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits>
#include <openssl/evp.h>
#include <stdexcept>
#include <streambuf>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <zlib.h>

#ifndef KPI_TRACE_ZLIB_BINARY_SHA256
#error "The selected trace decoder library must be pinned by the build"
#endif
#ifndef KPI_TRACE_ZLIB_HEADERS_SHA256
#error "The selected trace decoder headers must be pinned by the build"
#endif

namespace kpi::mpc {
namespace {
[[noreturn]] void fail(const char* category) { throw std::runtime_error(category); }

struct File {
    int value;
    explicit File(int fd) : value(fd) { if (fd < 0) fail("trace-artifact-file-open"); }
    ~File() { if (value >= 0) close(value); }
    File(const File&) = delete;
    File& operator=(const File&) = delete;
    File(File&& other) noexcept : value(other.release()) {}
    int release() { const auto fd = value; value = -1; return fd; }
};

class Digest {
    using Owned = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    Owned context_{EVP_MD_CTX_new(), EVP_MD_CTX_free};
public:
    Digest() {
        if (!context_ || EVP_DigestInit_ex(context_.get(), EVP_sha256(), nullptr) != 1)
            fail("trace-artifact-hash-init");
    }
    void add(const void* bytes, size_t length) {
        if (length && EVP_DigestUpdate(context_.get(), bytes, length) != 1)
            fail("trace-artifact-hash-update");
    }
    std::string finish() {
        std::array<unsigned char, EVP_MAX_MD_SIZE> bytes;
        unsigned length = 0;
        if (EVP_DigestFinal_ex(context_.get(), bytes.data(), &length) != 1 || length != 32)
            fail("trace-artifact-hash-final");
        constexpr char hex[] = "0123456789abcdef";
        std::string result;
        for (size_t i = 0; i < length; ++i) {
            result += hex[bytes[i] >> 4]; result += hex[bytes[i] & 15];
        }
        return result;
    }
};

ssize_t read_retry(int fd, void* data, size_t length) {
    ssize_t count;
    do { count = read(fd, data, length); } while (count < 0 && errno == EINTR);
    if (count < 0) fail("trace-artifact-read");
    return count;
}

size_t pread_retry(int fd, void* data, size_t length, size_t offset) {
    if (offset > static_cast<size_t>(std::numeric_limits<off_t>::max()))
        fail("trace-artifact-offset");
    ssize_t count;
    do { count = pread(fd, data, length, static_cast<off_t>(offset)); }
    while (count < 0 && errno == EINTR);
    if (count < 0) fail("trace-artifact-read");
    return static_cast<size_t>(count);
}

std::string public_file_hash(const char* path) {
    File file(open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC));
    struct stat metadata{};
    if (fstat(file.value, &metadata) || !S_ISREG(metadata.st_mode))
        fail("trace-decoder-library-file-type");
    Digest hash;
    std::array<char, 65536> buffer;
    for (;;) {
        const auto count = read_retry(file.value, buffer.data(), buffer.size());
        if (!count) return hash.finish();
        hash.add(buffer.data(), static_cast<size_t>(count));
    }
}

std::string admitted_decoder() {
    if (std::strcmp(zlibVersion(), ZLIB_VERSION) != 0)
        fail("trace-decoder-version");
    Dl_info loaded{};
    const auto symbol = dlsym(RTLD_DEFAULT, "inflate");
    if (!symbol || !dladdr(symbol, &loaded) || !loaded.dli_fname ||
        public_file_hash(loaded.dli_fname) != KPI_TRACE_ZLIB_BINARY_SHA256)
        fail("trace-decoder-library-identity");
    const std::string body = std::string("KPI_SINGLE_MEMBER_GZIP_ZLIB_V1\n") +
        ZLIB_VERSION + "\n" + KPI_TRACE_ZLIB_BINARY_SHA256 + "\n" +
        KPI_TRACE_ZLIB_HEADERS_SHA256 + "\n" + std::to_string(zlibCompileFlags()) + "\n";
    Digest hash; hash.add(body.data(), body.size()); return hash.finish();
}

class ArtifactBuffer : public std::streambuf {
    File file_;
    const size_t bytes_;
    const bool gzip_;
    size_t cursor_ = 0;
    bool complete_ = false;
    z_stream state_{};
    std::array<unsigned char, 65536> encoded_{};
    std::array<char, 65536> decoded_{};

    void refill() {
        if (state_.avail_in || cursor_ == bytes_) return;
        const auto count = pread_retry(file_.value, encoded_.data(),
                                      std::min(encoded_.size(), bytes_ - cursor_), cursor_);
        if (!count) fail("trace-artifact-snapshot-truncated");
        cursor_ += count;
        state_.next_in = encoded_.data(); state_.avail_in = static_cast<uInt>(count);
    }
protected:
    int_type underflow() override {
        if (gptr() < egptr()) return traits_type::to_int_type(*gptr());
        if (complete_) return traits_type::eof();
        if (!gzip_) {
            const auto count = pread_retry(file_.value, decoded_.data(),
                std::min(decoded_.size(), bytes_ - cursor_), cursor_);
            if (!count) {
                if (cursor_ != bytes_) fail("trace-artifact-snapshot-truncated");
                complete_ = true; return traits_type::eof();
            }
            cursor_ += count;
            setg(decoded_.data(), decoded_.data(), decoded_.data() + count);
            return traits_type::to_int_type(*gptr());
        }
        state_.next_out = reinterpret_cast<unsigned char*>(decoded_.data());
        state_.avail_out = static_cast<uInt>(decoded_.size());
        while (state_.avail_out == decoded_.size() && !complete_) {
            refill();
            const auto before = state_.avail_in;
            const int status = inflate(&state_, Z_NO_FLUSH);
            if (status == Z_STREAM_END) {
                // A canonical container has one complete gzip member. Reject
                // concatenated streams and opaque bytes after its CRC/footer.
                if (state_.avail_in || cursor_ != bytes_)
                    fail("trace-gzip-trailing-container-data");
                complete_ = true;
            } else if (status != Z_OK && status != Z_BUF_ERROR) {
                fail("trace-gzip-invalid-or-corrupt");
            } else if (!state_.avail_out) {
                break;
            } else if (before == state_.avail_in && state_.avail_out == decoded_.size()) {
                fail(cursor_ == bytes_ && !state_.avail_in ? "trace-gzip-truncated" :
                                                        "trace-gzip-decoder-stalled");
            }
        }
        const auto count = decoded_.size() - state_.avail_out;
        if (!count) return traits_type::eof();
        setg(decoded_.data(), decoded_.data(), decoded_.data() + count);
        return traits_type::to_int_type(*gptr());
    }
public:
    ArtifactBuffer(File fd, size_t bytes, bool gzip) : file_(std::move(fd)), bytes_(bytes), gzip_(gzip) {
        setg(decoded_.data(), decoded_.data(), decoded_.data());
        if (gzip_ && inflateInit2(&state_, 15 + 16) != Z_OK)
            fail("trace-gzip-initialize");
    }
    ~ArtifactBuffer() override { if (gzip_) inflateEnd(&state_); }
};

class ArtifactInput : public std::istream {
    ArtifactBuffer buffer_;
public:
    ArtifactInput(File fd, size_t bytes, bool gzip)
        : std::istream(nullptr), buffer_(std::move(fd), bytes, gzip) {
        rdbuf(&buffer_); exceptions(std::ios::badbit);
    }
};
}  // namespace

struct SealedTraceArtifact::Impl {
    File snapshot;
    size_t container_bytes = 0;
    size_t canonical_bytes = 0;
    bool gzip = false;
    std::string container_sha256, canonical_sha256, decoder_identity;
    explicit Impl(File fd) : snapshot(std::move(fd)) {}
};

SealedTraceArtifact::SealedTraceArtifact(std::unique_ptr<Impl> value) : impl_(std::move(value)) {}
SealedTraceArtifact::~SealedTraceArtifact() = default;

std::shared_ptr<const SealedTraceArtifact> SealedTraceArtifact::load(const std::filesystem::path& path) {
    return from_fd(open(path.c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC), false);
}

std::shared_ptr<const SealedTraceArtifact> SealedTraceArtifact::adopt_sealed_fd(int fd) {
    return from_fd(fcntl(fd, F_DUPFD_CLOEXEC, 0), true);
}

std::shared_ptr<const SealedTraceArtifact> SealedTraceArtifact::from_fd(int owned_fd, bool require_sealed) {
    File input(owned_fd);
    struct stat before{};
    if (fstat(input.value, &before) || !S_ISREG(before.st_mode) || before.st_size < 0)
        fail("trace-artifact-file-type");
    const auto declared_bytes = static_cast<size_t>(before.st_size);
    if (static_cast<off_t>(declared_bytes) != before.st_size)
        fail("trace-artifact-length-overflow");
    constexpr int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    auto finish = [&](File sealed, size_t count, std::string container_hash)
        -> std::shared_ptr<const SealedTraceArtifact> {
        auto impl = std::make_unique<Impl>(std::move(sealed));
        impl->container_bytes = count; impl->container_sha256 = std::move(container_hash);
        std::array<unsigned char, 2> magic{};
        const auto magic_bytes = pread_retry(impl->snapshot.value, magic.data(), magic.size(), 0);
        impl->gzip = magic_bytes == 2 && magic[0] == 0x1f && magic[1] == 0x8b;
        impl->decoder_identity = admitted_decoder();
        auto result = std::shared_ptr<SealedTraceArtifact>(new SealedTraceArtifact(std::move(impl)));
        auto stream = result->stream();
        std::array<char, 65536> buffer;
        Digest canonical;
        while (*stream) {
            stream->read(buffer.data(), buffer.size());
            const auto size = static_cast<size_t>(stream->gcount());
            if (result->impl_->canonical_bytes > std::numeric_limits<size_t>::max() - size)
                fail("trace-artifact-canonical-length-overflow");
            result->impl_->canonical_bytes += size; canonical.add(buffer.data(), size);
        }
        if (!stream->eof()) fail("trace-artifact-canonical-read");
        result->impl_->canonical_sha256 = canonical.finish();
        return result;
    };
    const int existing_seals = fcntl(input.value, F_GET_SEALS);
    if (existing_seals >= 0 && (existing_seals & seals) == seals) {
        // Seals may have been added concurrently after our first fstat. Once
        // all four are observed the content and length cannot change; reject
        // any intervening resize instead of hashing an earlier file prefix.
        struct stat sealed{};
        if (fstat(input.value, &sealed) || before.st_dev != sealed.st_dev ||
            before.st_ino != sealed.st_ino || before.st_size != sealed.st_size)
            fail("trace-artifact-changed-before-sealed-adoption");
        Digest hash;
        std::array<char, 65536> buffer;
        size_t cursor = 0;
        while (cursor < declared_bytes) {
            const auto size = pread_retry(input.value, buffer.data(),
                std::min(buffer.size(), declared_bytes - cursor), cursor);
            if (!size) fail("trace-artifact-snapshot-truncated");
            hash.add(buffer.data(), size); cursor += size;
        }
        return finish(std::move(input), declared_bytes, hash.finish());
    }
    if (require_sealed) fail("trace-artifact-adoption-requires-kernel-seals");
    File snapshot(memfd_create("kpi-public-trace", MFD_CLOEXEC | MFD_ALLOW_SEALING));
    Digest hash;
    size_t count = 0;
    std::array<char, 65536> buffer;
    for (;;) {
        const auto size = read_retry(input.value, buffer.data(), buffer.size());
        if (!size) break;
        if (count > std::numeric_limits<size_t>::max() - static_cast<size_t>(size))
            fail("trace-artifact-length-overflow");
        count += static_cast<size_t>(size); hash.add(buffer.data(), static_cast<size_t>(size));
        size_t at = 0;
        while (at < static_cast<size_t>(size)) {
            ssize_t written;
            do { written = write(snapshot.value, buffer.data() + at, static_cast<size_t>(size) - at); }
            while (written < 0 && errno == EINTR);
            if (written <= 0) fail("trace-artifact-sealed-copy");
            at += static_cast<size_t>(written);
        }
    }
    struct stat after{};
    if (fstat(input.value, &after) || before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_size != after.st_size || declared_bytes != count ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec)
        fail("trace-artifact-changed-during-copy");
    if (fcntl(snapshot.value, F_ADD_SEALS, seals) || fcntl(snapshot.value, F_GET_SEALS) != seals)
        fail("trace-artifact-kernel-seal");
    return finish(std::move(snapshot), count, hash.finish());
}

std::unique_ptr<std::istream> SealedTraceArtifact::stream() const {
    File duplicate(fcntl(impl_->snapshot.value, F_DUPFD_CLOEXEC, 0));
    return std::make_unique<ArtifactInput>(std::move(duplicate),
                                         impl_->container_bytes, impl_->gzip);
}
size_t SealedTraceArtifact::container_bytes() const { return impl_->container_bytes; }
size_t SealedTraceArtifact::canonical_bytes() const { return impl_->canonical_bytes; }
const std::string& SealedTraceArtifact::container_sha256() const { return impl_->container_sha256; }
const std::string& SealedTraceArtifact::canonical_sha256() const { return impl_->canonical_sha256; }
const std::string& SealedTraceArtifact::decoder_identity() const { return impl_->decoder_identity; }
bool SealedTraceArtifact::gzip() const { return impl_->gzip; }

}  // namespace kpi::mpc
