#include "financial_assignment.hpp"
#include "construction.hpp"
#include "streamed_h_map.hpp"
#include "../auth_groups.hpp"
#include "../packed/gzip_queries.hpp"
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <future>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(INSECURE) || defined(NDEBUG) || defined(DEBUG_MAC) || defined(PRINT_MAC) || defined(KPI_STREAMED_H_MAP_PUBLIC_FIXTURE_CONTROL)
#error "Financial proving excludes insecure and public fixture entry points"
#endif

extern char** environ;

namespace kpi::mpc {
// Identical implementation-private friend definition as the qualified prover.
struct FinalProofAccess {
    static G1Value a(const G1ServerOpened& point) { return point.point_; }
};
}

namespace kpi::mpc::financial {
namespace {
constexpr const char* approved_verifier_sha256 =
    "c1805cfe7ae9b2db7d58fd58727b57e92a0fec866506cd720fbd59242359131f";
constexpr size_t local_point_workers = 3;
constexpr size_t public_point_chunk = 1024;

class Descriptor {
    int fd_;
public:
    explicit Descriptor(int fd) : fd_(fd) {
        if (fd < 0) throw std::runtime_error("financial-public-verifier-file");
    }
    ~Descriptor() { close(fd_); }
    Descriptor(const Descriptor&) = delete;
    int get() const { return fd_; }
    std::string inherited_path() const { return "/proc/self/fd/" + std::to_string(fd_); }
};

std::vector<unsigned char> bounded_public_bytes(int fd, size_t limit) {
    struct stat status{};
    if (fstat(fd, &status) || !S_ISREG(status.st_mode) || status.st_size < 0 ||
        static_cast<uint64_t>(status.st_size) > limit)
        throw std::runtime_error("financial-public-file-shape");
    std::vector<unsigned char> result(static_cast<size_t>(status.st_size));
    size_t offset = 0;
    while (offset < result.size()) {
        const auto count = pread(fd, result.data() + offset, result.size() - offset, offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) throw std::runtime_error("financial-public-file-read");
        offset += static_cast<size_t>(count);
    }
    return result;
}

std::string public_inputs_csv(const history::Digest& effects) {
    std::string csv;
    for (size_t part = 0; part < 2; ++part) {
        bigint value;
        mpz_import(value.get_mpz_t(), 16, -1, 1, 0, 0, effects.data() + 16 * part);
        if (part) csv += ',';
        csv += value.get_str();
    }
    return csv;
}

void verify_candidate(const std::filesystem::path& metadata_path,
    const std::filesystem::path& vk_path, const std::filesystem::path& verifier_path,
    const std::filesystem::path& candidate_path, const std::string& model_identity,
    const std::string& vk_identity, const history::Digest& effects,
    const std::array<unsigned char, 128>& proof) {
    // These inherited descriptors fix the exact admitted bytes across exec;
    // no caller-provided success function or exit-code override is accepted.
    Descriptor metadata(open(metadata_path.c_str(), O_RDONLY | O_NOFOLLOW));
    Descriptor vk(open(vk_path.c_str(), O_RDONLY | O_NOFOLLOW));
    Descriptor verifier(open(verifier_path.c_str(), O_RDONLY | O_NOFOLLOW));
    if (sha256_hex(bounded_public_bytes(metadata.get(), 744)) != model_identity ||
        sha256_hex(bounded_public_bytes(vk.get(), 328)) != vk_identity ||
        sha256_hex(bounded_public_bytes(verifier.get(), 64 * 1024 * 1024)) != approved_verifier_sha256)
        throw std::runtime_error("financial-independent-verifier-or-model-identity");
    Descriptor candidate(open(candidate_path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, 0600));
    struct CandidateCleanup {
        const std::filesystem::path& path;
        ~CandidateCleanup() { unlink(path.c_str()); }
    } cleanup{candidate_path};
    struct stat status{};
    if (fstat(candidate.get(), &status) || !S_ISREG(status.st_mode) || status.st_nlink != 1 ||
        (status.st_mode & 0777) != 0600 || status.st_size != 0)
        throw std::runtime_error("financial-private-candidate-shape");
    size_t written = 0;
    while (written < proof.size()) {
        const auto count = write(candidate.get(), proof.data() + written, proof.size() - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) throw std::runtime_error("financial-private-candidate-write");
        written += static_cast<size_t>(count);
    }
    if (fsync(candidate.get()) != 0) throw std::runtime_error("financial-private-candidate-persistence");
    const auto metadata_fd = metadata.inherited_path(), vk_fd = vk.inherited_path();
    const auto proof_fd = candidate.inherited_path(), csv = public_inputs_csv(effects);
    const auto child = fork();
    if (child == -1) throw std::runtime_error("financial-independent-verifier-launch");
    if (child == 0) {
        const int sink = open("/dev/null", O_WRONLY);
        if (sink < 0 || dup2(sink, STDOUT_FILENO) < 0 || dup2(sink, STDERR_FILENO) < 0) _exit(126);
        close(sink);
        char* argv[] = {const_cast<char*>("kpi-mascot-public-model"), const_cast<char*>("verify-packed"),
            const_cast<char*>(metadata_fd.c_str()), const_cast<char*>(vk_fd.c_str()),
            const_cast<char*>(proof_fd.c_str()), const_cast<char*>(csv.c_str()),
            const_cast<char*>(model_identity.c_str()), nullptr};
        fexecve(verifier.get(), argv, environ);
        _exit(127);
    }
    int result = 0;
    while (waitpid(child, &result, 0) == -1)
        if (errno != EINTR) throw std::runtime_error("financial-independent-verifier-wait");
    if (!WIFEXITED(result) || WEXITSTATUS(result) != 0 ||
        sha256_hex(bounded_public_bytes(metadata.get(), 744)) != model_identity ||
        sha256_hex(bounded_public_bytes(vk.get(), 328)) != vk_identity ||
        sha256_hex(bounded_public_bytes(verifier.get(), 64 * 1024 * 1024)) != approved_verifier_sha256 ||
        bounded_public_bytes(candidate.get(), 128) != std::vector<unsigned char>(proof.begin(), proof.end()))
        throw std::runtime_error("financial-independent-Ark-verification-refused");
}

template<class Group>
auto local_point_sum(std::span<const Group> points, std::span<const AuthScalar> scalars) {
    using Result = decltype(public_point_map(points[0], scalars[0]));
    if (points.size() != scalars.size() || points.empty() || points.size() > public_point_chunk)
        throw std::runtime_error("financial-local-point-chunk-shape");
    std::vector<std::future<Result>> workers;
    const auto count = std::min(local_point_workers, points.size());
    for (size_t worker = 0; worker < count; ++worker) {
        const auto first = points.size() * worker / count;
        const auto last = points.size() * (worker + 1) / count;
        // No Player, preprocessing, opening or MascotContext is captured.
        // Both private scalar lanes retain NativePoint::mul(...,true).
        workers.push_back(std::async(std::launch::async, [points, scalars, first, last] {
            Result result;
            for (size_t i = first; i < last; ++i)
                result += public_point_map(points[i], scalars[i]);
            return result;
        }));
    }
    Result total;
    for (auto& worker : workers) total += worker.get();
    return total;
}

AuthG1 query_g1(packed::GzipQueryCursor& cursor, packed::Query kind,
               std::span<const AuthScalar> scalars, uint64_t points) {
    if ((kind == packed::Query::H && points + 1 != scalars.size()) ||
        (kind != packed::Query::H && points != scalars.size()))
        throw std::runtime_error("financial-G1-query-arity");
    AuthG1 sum;
    for (uint64_t first = 0; first < points;) {
        const auto count = static_cast<size_t>(std::min(uint64_t(public_point_chunk), points - first));
        std::vector<G1Value> chunk;
        chunk.reserve(count);
        for (size_t i = 0; i < count; ++i) chunk.push_back(cursor.next_g1(kind));
        sum += local_point_sum(std::span<const G1Value>(chunk), scalars.subspan(static_cast<size_t>(first), count));
        first += count;
    }
    return sum;
}

AuthG2 query_g2(packed::GzipQueryCursor& cursor, std::span<const AuthScalar> scalars,
               uint64_t points) {
    if (points != scalars.size()) throw std::runtime_error("financial-G2-query-arity");
    AuthG2 sum;
    for (uint64_t first = 0; first < points;) {
        const auto count = static_cast<size_t>(std::min(uint64_t(public_point_chunk), points - first));
        std::vector<G2Value> chunk;
        chunk.reserve(count);
        for (size_t i = 0; i < count; ++i) chunk.push_back(cursor.next_g2());
        sum += local_point_sum(std::span<const G2Value>(chunk), scalars.subspan(static_cast<size_t>(first), count));
        first += count;
    }
    return sum;
}
}

std::array<unsigned char, 128> FinancialValidatedAssignment::make_candidate(
    MascotContext& context, history::PreparedEpochTicket& prepared) {
    require_same(context, *construction_);
    if (!preparation_claimed_ || proof_claimed_ || !prepared_effects_)
        throw std::runtime_error("financial-proof-capability-state");
    proof_claimed_ = true;
    prepared.consume_for_proof(context, attempt_, identity_, construction_->binding_identity(), *prepared_effects_);
    const auto& model = construction_->model();
    const auto& metadata = model.metadata();
    if (metadata.prefix_mode != packed::PrefixMode::SecretDerivedRecipe)
        throw std::runtime_error("financial-proof-derived-prefix-required");
    const auto assignment = construction_->assignment();
    const auto schedule = std::string("KPI_FINANCIAL_CONSTANT_TIME_LOCAL_QUERY_V1\n") +
        model.identity() + "\n" + std::to_string(local_point_workers) + "\n" +
        std::to_string(public_point_chunk) + "\n";
    context.agree_public_bytes("financial-local-query-schedule", {
        reinterpret_cast<const unsigned char*>(schedule.data()), schedule.size()});
    const auto h = StreamedWitnessMap::compute(context, model, assignment, batch_);
    const auto r = context.random_auth(), s = context.random_auth();
    const std::array<AuthScalar, 1> rv{r}, sv{s};
    const auto rs = context.multiply_batch(rv, sv).at(0);
    const auto delta1 = model.base_g1(packed::BaseG1::Delta);
    const auto delta2 = model.base_g2(packed::BaseG2::Delta);
    auto queries = model.query_cursor();
    auto a = query_g1(queries, packed::Query::A, assignment, model.query_size(packed::Query::A));
    a += public_point_map(delta1, r);
    add_public(a, model.base_g1(packed::BaseG1::Alpha), context);
    context.report_public_phase("financial-A-query-complete");
    auto b1 = query_g1(queries, packed::Query::B1, assignment, model.query_size(packed::Query::B1));
    b1 += public_point_map(delta1, s);
    add_public(b1, model.base_g1(packed::BaseG1::Beta), context);
    context.report_public_phase("financial-B1-query-complete");
    auto b2 = query_g2(queries, assignment, model.query_size(packed::Query::B2));
    b2 += public_point_map(delta2, s);
    add_public(b2, model.base_g2(packed::BaseG2::Beta), context);
    context.report_public_phase("financial-B2-query-complete");
    const auto h_point = query_g1(queries, packed::Query::H, h, model.query_size(packed::Query::H));
    const auto l = query_g1(queries, packed::Query::L,
        assignment.subspan(static_cast<size_t>(metadata.instances)), model.query_size(packed::Query::L));
    queries.finish();
    model.check_backing_unchanged();
    context.check_field_pending();
    GroupMacSetup checks(context.player());
    const auto [opened_a, opened_b1] = open_checked_g1_pair(context, a, b1);
    context.report_public_phase("financial-masked-A-and-B1-MAC-checked");
    auto c = server_opened_point_map(opened_a, s);
    c += server_opened_point_map(opened_b1, r);
    c -= public_point_map(delta1, rs);
    c += h_point;
    c += l;
    const auto [opened_c, opened_b2] = open_checked_g1_g2(context, c, b2);
    context.report_public_phase("financial-final-B2-and-C-MAC-checked");
    ProofPublic proof{FinalProofAccess::a(opened_a), opened_b2, opened_c};
    const auto encoded = encode_native_proof(proof);
    const auto decoded = decode_native_proof(encoded);
    if (decoded.a != proof.a || decoded.b != proof.b || decoded.c != proof.c)
        throw std::runtime_error("financial-native-proof-roundtrip");
    context.agree_public_bytes("financial-complete-native128-proof", encoded);
    context.check_field_pending();
    model.check_backing_unchanged();
    return encoded;
}

VerifiedFinancialProof::VerifiedFinancialProof(MascotContext& context,
    std::shared_ptr<const FinancialConstruction> construction, history::AttemptBinding attempt,
    std::string validation, std::string construction_identity, history::Digest effects,
    std::array<unsigned char, 128> proof)
    : context_(&context), generation_(context.generation()), epoch_(context.failure_epoch()),
      construction_(std::move(construction)), attempt_(std::move(attempt)),
      validation_identity_(std::move(validation)), construction_identity_(std::move(construction_identity)),
      effects_(effects), proof_(proof) {}

VerifiedFinancialProof prove_and_verify_financial(MascotContext& context,
    FinancialValidatedAssignment&& validated, history::PreparedEpochTicket&& prepared,
    const std::filesystem::path& metadata, const std::filesystem::path& vk,
    const std::filesystem::path& verifier, const std::filesystem::path& candidate) {
    context.require_healthy();
    try {
        const auto proof = validated.make_candidate(context, prepared);
        const auto effects = *validated.prepared_effects_;
        verify_candidate(metadata, vk, verifier, candidate, history::hex(validated.attempt_.model),
            validated.verifying_key_identity(), effects, proof);
        std::vector<unsigned char> verified(proof.begin(), proof.end());
        verified.insert(verified.end(), effects.begin(), effects.end());
        context.agree_public_bytes("financial-all-three-independent-Ark-verified", verified);
        context.check_field_pending();
        context.report_public_phase("financial-independent-Ark-verification-complete");
        return VerifiedFinancialProof(context, validated.construction_, validated.attempt_,
            validated.identity_, validated.construction_->binding_identity(), effects, proof);
    } catch (...) { context.poison(); throw; }
}
}  // namespace kpi::mpc::financial
