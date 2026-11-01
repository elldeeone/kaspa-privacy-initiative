#include "baseline_owner_truth_capsule_bridge.hpp"
#include "baseline_owner_truth_capsule_schema.hpp"

#include "authenticated_baseline_owner_receiver.hpp"
#include "../../private_batch_trial/privacy_measurement_worker_capsule.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <openssl/crypto.h>
#include <span>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpi::mpc::financial::registered_driver::baseline_disclosure {
namespace {
using Bytes = std::vector<unsigned char>;
using Endpoint = kpb::measurement::runtime_bridge::
    MeasurementInputEndpointAuthority;
using EndpointKind = kpb::measurement::runtime_bridge::MeasurementInputKind;
using PublicEndpoint = kpb::measurement::runtime_bridge::
    PublicMeasurementInputEndpoint;

struct FeederRound {
    unsigned round{};
    Digest run{}, attempt{}, cohort{}, capture_plan{}, projection{}, context{};
    Digest nullifier{};
    std::array<Digest, 2> tuple_hashes{}, tuple_commitments{};
};

struct FeederTruth {
    unsigned owner{};
    Digest trial{};
    std::array<FeederRound, 2> rounds{};
};

class TruthCleanseGuard final {
    void* rounds_{};
    std::size_t rounds_bytes_{};
    void* sessions_{};
    std::size_t sessions_bytes_{};
    FeederTruth* feeder_{};
public:
    TruthCleanseGuard(
            void* rounds, std::size_t rounds_bytes,
            void* sessions, std::size_t sessions_bytes)
        : rounds_(rounds), rounds_bytes_(rounds_bytes),
          sessions_(sessions), sessions_bytes_(sessions_bytes) {}
    TruthCleanseGuard(const TruthCleanseGuard&) = delete;
    TruthCleanseGuard& operator=(const TruthCleanseGuard&) = delete;
    void attach(FeederTruth& feeder) { feeder_ = &feeder; }
    ~TruthCleanseGuard() {
        if (feeder_) OPENSSL_cleanse(feeder_, sizeof(*feeder_));
        OPENSSL_cleanse(rounds_, rounds_bytes_);
        OPENSSL_cleanse(sessions_, sessions_bytes_);
    }
};

[[noreturn]] void refuse() { throw identity_registry::Refused(); }
void need(bool value) { if (!value) refuse(); }
bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

void close_fd(int& fd) noexcept {
    if (fd < 0) return;
    while (::close(fd) != 0 && errno == EINTR) {}
    fd = -1;
}

class Fd final {
    int value_{-1};
public:
    Fd() = default;
    explicit Fd(int value) : value_(value) {}
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& other) noexcept : value_(other.release()) {}
    ~Fd() { close_fd(value_); }
    int get() const { return value_; }
    int release() { return std::exchange(value_, -1); }
    void reset() { close_fd(value_); }
};

Digest random_digest() {
    Digest result{};
    std::size_t at = 0;
    while (at < result.size()) {
        const auto count = ::getrandom(
            result.data() + at, result.size() - at, 0);
        if (count < 0 && errno == EINTR) continue;
        need(count > 0);
        at += static_cast<std::size_t>(count);
    }
    need(nonzero(result));
    return result;
}

void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}
void add(Bytes& out, const char* value) {
    while (*value) out.push_back(static_cast<unsigned char>(*value++));
}
void integer(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}

Digest feeder_exit_identity(
        const Digest& endpoint_identity, const Digest& feeder_session,
        unsigned owner, std::int64_t pid) {
    need(pid > 1 && owner < 3);
    Bytes bytes;
    add(bytes, "KPB_BASELINE_OWNER_TRUTH_FEEDER_EXIT_V1\n");
    add(bytes, endpoint_identity); add(bytes, feeder_session);
    integer(bytes, owner); integer(bytes, static_cast<std::uint64_t>(pid));
    integer(bytes, truth_capsule_schema::PACKET_BYTES);
    return identity_registry::digest(bytes);
}

template<std::size_t N>
void put(std::array<unsigned char, N>& out, std::size_t& at,
         std::span<const unsigned char> value) noexcept {
    if (at > out.size() || value.size() > out.size() - at) _exit(91);
    for (const auto byte : value) out[at++] = byte;
}

template<std::size_t N>
void put_byte(std::array<unsigned char, N>& out, std::size_t& at,
              unsigned value) noexcept {
    if (value > 255 || at >= out.size()) _exit(92);
    out[at++] = static_cast<unsigned char>(value);
}

[[noreturn]] void feed(
        int fd, const FeederTruth& selected,
        const Digest& endpoint_identity, const Digest& feeder_session) noexcept {
    std::array<unsigned char, truth_capsule_schema::PACKET_BYTES> packet{};
    std::size_t at = 0;
    put(packet, at, truth_capsule_schema::MAGIC);
    put_byte(packet, at, truth_capsule_schema::VERSION);
    static_assert(static_cast<unsigned>(
        kpb::measurement::Classification::TransparentBaseline) ==
        truth_capsule_schema::EXPLICIT_BASELINE_CLASSIFICATION);
    put_byte(packet, at, static_cast<unsigned>(
        kpb::measurement::Classification::TransparentBaseline));
    put_byte(packet, at, selected.owner);
    put(packet, at, endpoint_identity); put(packet, at, feeder_session);
    put(packet, at, selected.trial);
    for (const auto& round : selected.rounds) {
        put_byte(packet, at, round.round);
        for (const auto* value : {
                 &round.run, &round.attempt, &round.cohort,
                 &round.capture_plan, &round.projection, &round.context,
                 &round.nullifier, &round.tuple_hashes[0],
                 &round.tuple_hashes[1], &round.tuple_commitments[0],
                 &round.tuple_commitments[1]})
            put(packet, at, *value);
    }
    if (at != packet.size()) _exit(93);
    ssize_t sent;
    do {
        sent = ::send(fd, packet.data(), packet.size(), MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    OPENSSL_cleanse(packet.data(), packet.size());
    if (sent != static_cast<ssize_t>(packet.size())) _exit(94);
    while (::close(fd) != 0 && errno == EINTR) {}
    _exit(0);
}

} // namespace

kpb::measurement::runtime_bridge::MeasurementInputEndpointAuthority
BaselineOwnerTruthCapsuleBridge::prepare(
        OwnerScoreTruthAuthority&& supplied,
        const kpb::measurement::PublicOwnerTruthReleasePermit& release) {
    need(supplied.live_.load());
    const auto& first = supplied.rounds_[0];
    const auto& second = supplied.rounds_[1];
    need(first.owner < 3 && second.owner == first.owner &&
         first.round == 1 && second.round == 2 &&
         first.run != second.run && first.trial == second.trial &&
         first.attempt != second.attempt && first.cohort != second.cohort &&
         first.capture_plan_identity != second.capture_plan_identity &&
         first.projection_identity != second.projection_identity &&
         first.context_identity != second.context_identity &&
         first.logical_owner_identity == second.logical_owner_identity &&
         first.roster_authority_identity ==
             second.roster_authority_identity &&
         first.roster_root_identity == second.roster_root_identity);
    for (const auto& round : supplied.rounds_)
        for (const auto* value : {
                 &round.run, &round.trial, &round.attempt, &round.cohort,
                 &round.capture_plan_identity, &round.projection_identity,
                 &round.context_identity, &round.public_nullifier,
                 &round.public_tuple_hashes[0],
                 &round.public_tuple_hashes[1],
                 &round.public_tuple_commitments[0],
                 &round.public_tuple_commitments[1]})
            need(nonzero(*value));
    need(supplied.live_.exchange(false));
    TruthCleanseGuard cleanse_guard(
        supplied.rounds_.data(), sizeof(supplied.rounds_),
        supplied.party_sessions_.data(), sizeof(supplied.party_sessions_));

    FeederTruth feeder{
        .owner = first.owner,
        .trial = first.trial,
        .rounds = {{
            FeederRound{
                .round = first.round,
                .run = first.run, .attempt = first.attempt,
                .cohort = first.cohort,
                .capture_plan = first.capture_plan_identity,
                .projection = first.projection_identity,
                .context = first.context_identity,
                .nullifier = first.public_nullifier,
                .tuple_hashes = first.public_tuple_hashes,
                .tuple_commitments = first.public_tuple_commitments,
            },
            FeederRound{
                .round = second.round,
                .run = second.run, .attempt = second.attempt,
                .cohort = second.cohort,
                .capture_plan = second.capture_plan_identity,
                .projection = second.projection_identity,
                .context = second.context_identity,
                .nullifier = second.public_nullifier,
                .tuple_hashes = second.public_tuple_hashes,
                .tuple_commitments = second.public_tuple_commitments,
            },
        }},
    };
    cleanse_guard.attach(feeder);

    const auto endpoint_identity = random_digest();
    const auto feeder_session = random_digest();
    const auto owner = first.owner;
    PublicEndpoint::PublicLineage lineage{
        .classification =
            kpb::measurement::Classification::TransparentBaseline,
        .trial = supplied.rounds_[0].trial,
        .barrier = release.barrier,
        .capture_plan_identities = {
            supplied.rounds_[0].capture_plan_identity,
            supplied.rounds_[1].capture_plan_identity},
        .financial_runs = {
            supplied.rounds_[0].run, supplied.rounds_[1].run},
        .round_attempts = {
            supplied.rounds_[0].attempt, supplied.rounds_[1].attempt},
        .round_cohorts = {
            supplied.rounds_[0].cohort, supplied.rounds_[1].cohort},
        .projections = {
            supplied.rounds_[0].projection_identity,
            supplied.rounds_[1].projection_identity},
    };

    int raw[2]{-1, -1};
    need(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, raw) == 0);
    Fd receiver(raw[0]), sender(raw[1]);
    int pass_credentials = 1;
    need(::setsockopt(receiver.get(), SOL_SOCKET, SO_PASSCRED,
                      &pass_credentials, sizeof(pass_credentials)) == 0);

    const pid_t feeder_pid = ::fork();
    if (feeder_pid < 0) refuse();
    if (feeder_pid == 0) {
        receiver.reset();
        feed(sender.release(), feeder, endpoint_identity, feeder_session);
    }
    sender.reset();

    int status = 0;
    pid_t waited;
    do { waited = ::waitpid(feeder_pid, &status, 0); }
    while (waited < 0 && errno == EINTR);
    need(waited == feeder_pid && WIFEXITED(status) &&
         WEXITSTATUS(status) == 0);

    const auto exit_identity = feeder_exit_identity(
        endpoint_identity, feeder_session, owner, feeder_pid);
    return Endpoint(
        EndpointKind::OwnerTruth, owner, receiver.get(), endpoint_identity,
        std::move(lineage), feeder_pid, feeder_session, exit_identity);
}

#ifdef KPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP
kpb::measurement::runtime_bridge::MeasurementInputEndpointAuthority
BaselineOwnerTruthCapsuleBridge::test_only_prepare(
        OwnerScoreTruthAuthority&& supplied,
        const kpb::measurement::PublicOwnerTruthReleasePermit& release) {
    return prepare(std::move(supplied), release);
}
#endif

} // namespace kpi::mpc::financial::registered_driver::baseline_disclosure
