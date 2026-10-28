// Public small-fixture controls. Never creates a private assignment or MPC context.
#include "gzip_queries.hpp"
#include "point_codec.hpp"
#include <fstream>
#include <iostream>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <zlib.h>

namespace {
using namespace kpi::mpc;
using namespace kpi::mpc::packed;
uint64_t controls = 0, compared = 0;
void require(bool value) { if (!value) throw std::runtime_error("gzip-control-assertion"); }
template<class F> void rejects(F&& f) {
    bool rejected = false;
    try { f(); } catch (const std::exception&) { rejected = true; }
    require(rejected); ++controls;
}
std::vector<unsigned char> read(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("gzip-control-public-file-open");
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}
void gzip(const std::filesystem::path& path, std::span<const unsigned char> input) {
    // Only explicit tiny PUBLIC fixtures may be materialized by this control.
    require(input.size() < 8 * 1024 * 1024);
    z_stream state{};
    require(deflateInit2(&state, 1, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) == Z_OK);
    state.next_in = const_cast<Bytef*>(input.data()); state.avail_in = static_cast<uInt>(input.size());
    std::vector<unsigned char> output(deflateBound(&state, input.size()));
    state.next_out = output.data(); state.avail_out = static_cast<uInt>(output.size());
    const auto result = deflate(&state, Z_FINISH); const auto size = state.total_out;
    deflateEnd(&state); require(result == Z_STREAM_END);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(output.data()), static_cast<std::streamsize>(size));
    require(out.good());
}
GzipQueryPins pins(const std::shared_ptr<const SealedTraceArtifact>& a, const std::string& vk) {
    return {a->container_sha256(), a->canonical_sha256(), a->decoder_identity(), vk,
            a->container_bytes(), a->canonical_bytes()};
}
bool same(const AffinePoint& a, const AffinePoint& b) {
    return a.infinity == b.infinity && a.x == b.x && a.y == b.y;
}
void compare(const PackedModel& raw, GzipQueryCursor& cursor) {
    for (auto q : {Query::A, Query::B1, Query::B2, Query::H, Query::L})
        for (uint64_t i = 0; i < raw.query_size(q); ++i) {
            const auto original = q == Query::B2 ? raw.g2_query(i).affine() : raw.g1_query(q, i).affine();
            const auto streamed = q == Query::B2 ? cursor.next_g2().affine() : cursor.next_g1(q).affine();
            require(same(original, streamed)); ++compared;
        }
    cursor.finish(); ++controls;
}
}
int main(int argc, char** argv) {
    try {
        if (argc != 6) throw std::runtime_error("gzip-control-arguments");
        const auto raw = PackedModel::admit(argv[1], argv[2], argv[3], argv[4]);
        const auto& meta = raw.metadata();
        const StockQueryShape shape{meta.instances, meta.witnesses, meta.domain};
        const auto pk = read(argv[2]), vk = read(argv[3]);
        const std::filesystem::path directory(argv[5]);
        std::filesystem::create_directory(directory);
        const auto encoded = directory / "public-stock-pk.gz";
        gzip(encoded, pk);
        auto artifact = SealedTraceArtifact::load(encoded);
        const auto expected = pins(artifact, meta.vk_sha256);
        const auto store = GzipQueryStore::admit(artifact, vk, shape, expected);
        RowsDescriptor rows{};
        rows.instances = meta.instances; rows.witnesses = meta.witnesses; rows.constraints = meta.constraints;
        rows.compressed_sha256 = meta.compressed_sha256; rows.raw_sha256 = meta.raw_sha256;
        rows.compressed_bytes = meta.compressed_bytes; rows.raw_bytes = meta.raw_bytes;
        rows.matrix_fingerprint = meta.matrix_fingerprint;
        for (unsigned i = 0; i < 3; ++i) rows.files[i] = std::filesystem::path(argv[1]) / (std::string(1, "ABC"[i]) + ".rows.gz");
        const auto packed = PackedModel::admit_compressed(argv[1], store, argv[3], argv[4], rows);
        require(packed.identity() == raw.identity());
        require(packed.query_transport_identity() == store.transport_identity());
        require(packed.admission_stats().g1_points == raw.admission_stats().g1_points);
        require(packed.admission_stats().g2_points == raw.admission_stats().g2_points);
        for (auto role : {BaseG1::Alpha, BaseG1::Beta, BaseG1::Delta}) require(same(raw.base_g1(role).affine(), packed.base_g1(role).affine()));
        for (auto role : {BaseG2::Beta, BaseG2::Gamma, BaseG2::Delta}) require(same(raw.base_g2(role).affine(), packed.base_g2(role).affine()));
        for (uint64_t i = 0; i < meta.instances; ++i) require(same(raw.vk_gamma_abc(i).affine(), packed.vk_gamma_abc(i).affine()));
        ++controls;
        auto first = packed.query_cursor(), independent = store.cursor();
        compare(raw, first); compare(raw, independent);
        rejects([&] { first.finish(); }); rejects([&] { (void) first.next_g1(Query::A); });
        auto early = store.cursor(); rejects([&] { early.finish(); });
        rejects([&] { (void) early.next_g1(Query::A); });
        auto wrong = store.cursor(); rejects([&] { (void) wrong.next_g1(Query::B1); });
        rejects([&] { (void) wrong.next_g1(Query::A); });
        auto group = store.cursor(); rejects([&] { (void) group.next_g2(); });
        auto moved_from = store.cursor(); auto moved = std::move(moved_from);
        rejects([&] { (void) moved_from.next_g1(Query::A); }); compare(raw, moved);
        rejects([&] { (void) packed.g1_query(Query::A, 0); });
        rejects([&] { (void) packed.g2_query(0); });
        rejects([&] { (void) raw.query_cursor(); });
        for (unsigned field = 0; field < 6; ++field) {
            auto bad = expected;
            const auto change = [](std::string& s) { s[0] = s[0] == '0' ? '1' : '0'; };
            if (field == 0) change(bad.container_sha256);
            if (field == 1) change(bad.canonical_pk_sha256);
            if (field == 2) change(bad.decoder_identity);
            if (field == 3) change(bad.vk_sha256);
            if (field == 4) ++bad.container_bytes;
            if (field == 5) ++bad.canonical_pk_bytes;
            rejects([&] { (void) GzipQueryStore::admit(artifact, vk, shape, bad); });
        }
        auto wrong_rows = rows; ++wrong_rows.constraints;
        rejects([&] { (void) PackedModel::admit_compressed(argv[1], store, argv[3], argv[4], wrong_rows); });
        rejects([&] { (void) PackedModel::admit_compressed(argv[1], store, argv[3], std::string(64, '0'), rows); });
        auto wrong_shape = shape; ++wrong_shape.witnesses;
        rejects([&] { (void) GzipQueryStore::admit(artifact, vk, wrong_shape, expected); });
        const size_t vector_start = vk.size() + 64;
        // Mutated public fixtures receive their own TRUE transport/hash pins;
        // rejection must therefore come from stock framing / point admission.
        const auto malformed = [&](std::vector<unsigned char> value) {
            const auto path = directory / "malformed-public-stock.gz"; gzip(path, value);
            auto a = SealedTraceArtifact::load(path);
            const auto p = pins(a, meta.vk_sha256);
            rejects([&] { (void) GzipQueryStore::admit(a, vk, shape, p); });
        };
        auto bad = pk; bad[vector_start] ^= 1; malformed(bad);
        bad = pk; bad[vector_start + 8 + 31] |= 0xc0; malformed(bad);
        bad = pk; std::fill(bad.begin() + vector_start + 8, bad.begin() + vector_start + 40, 0xff);
        bad[vector_start + 39] = 0x3f; malformed(bad);
        bad = pk; bad.back() |= 0xc0; malformed(bad);
        bad = pk; bad.push_back(0); malformed(bad);
        bad = pk; bad.pop_back(); malformed(bad);
        bad = pk; bad[0] ^= 1; malformed(bad);
        auto short_vk = vk; short_vk.pop_back();
        rejects([&] { (void) GzipQueryStore::admit(artifact, short_vk, shape, expected); });
        auto different_vk = vk; different_vk[0] ^= 1;
        rejects([&] { (void) GzipQueryStore::admit(artifact, different_vk, shape, expected); });
        // Adopting duplicates an already sealed descriptor and outlives caller.
        const auto encoded_bytes = read(encoded);
        const int fd = memfd_create("public-gzip-query-control", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        require(fd >= 0);
        require(write(fd, encoded_bytes.data(), encoded_bytes.size()) == static_cast<ssize_t>(encoded_bytes.size()));
        rejects([&] { (void) SealedTraceArtifact::adopt_sealed_fd(fd); });
        require(fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == 0);
        auto adopted = SealedTraceArtifact::adopt_sealed_fd(fd); close(fd);
        const auto shared = GzipQueryStore::admit(adopted, vk, shape, expected);
        artifact.reset(); adopted.reset();
        auto lifetime = shared.cursor(); compare(raw, lifetime);
        std::cout << "{\"schema\":\"kpi-gzip-query-controls/v1\",\"status\":\"PASS\",\"controls\":" << controls
            << ",\"compared_query_points\":" << compared << ",\"transport_identity\":\"" << store.transport_identity()
            << "\",\"private_input_or_MPC_or_setup_executed\":false}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "public-gzip-query-control-refused: " << error.what() << '\n'; return 1;
    }
}
