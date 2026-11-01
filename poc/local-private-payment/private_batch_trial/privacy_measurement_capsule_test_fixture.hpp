#pragma once

#include "privacy_measurement_worker_capsule.hpp"

#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <fstream>
#include <openssl/sha.h>
#include <span>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kpb::measurement::runtime_bridge::test_fixture {

using Bytes = std::vector<unsigned char>;

inline Digest digest(unsigned char value) {
    Digest result{};
    result.fill(value);
    return result;
}

inline Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    assert(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return result;
}

inline Digest file_hash(const std::string& path) {
    std::ifstream stream(path, std::ios::binary);
    assert(stream.good());
    Bytes value((std::istreambuf_iterator<char>(stream)),
                std::istreambuf_iterator<char>());
    assert(!value.empty());
    return hash(value);
}

inline void integer(Bytes& out, std::uint64_t value, unsigned width) {
    for (unsigned offset = 0; offset < width; ++offset)
        out.push_back(static_cast<unsigned char>(value >> (8 * offset)));
}

inline void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}

inline Bytes archive(bool source) {
    constexpr std::array<unsigned char, 8> source_magic{
        'K', 'P', 'B', 'S', 'R', 'C', '1', 0};
    constexpr std::array<unsigned char, 8> asset_magic{
        'K', 'P', 'B', 'A', 'S', 'T', '1', 0};
    constexpr std::array<unsigned char, 10> path{
        'w', 'o', 'r', 'k', 'e', 'r', '.', 'b', 'i', 'n'};
    const std::array<unsigned char, 4> content{
        static_cast<unsigned char>(source ? 1 : 5), 2, 3, 4};
    Bytes result;
    add(result, source ? std::span<const unsigned char>(source_magic)
                       : std::span<const unsigned char>(asset_magic));
    integer(result, 1, 4);
    integer(result, path.size(), 2);
    integer(result, content.size(), 8);
    add(result, path);
    add(result, hash(content));
    add(result, content);
    return result;
}

inline void write_all(int fd, std::span<const unsigned char> value) {
    std::size_t at = 0;
    while (at < value.size()) {
        const auto count = ::write(fd, value.data() + at, value.size() - at);
        if (count < 0 && errno == EINTR) continue;
        assert(count > 0);
        at += static_cast<std::size_t>(count);
    }
}

class Fd final {
    int value_{-1};
public:
    explicit Fd(int value = -1) : value_(value) {}
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& other) noexcept : value_(std::exchange(other.value_, -1)) {}
    ~Fd() { if (value_ >= 0) ::close(value_); }
    int get() const { return value_; }
};

inline Fd memory_file(const Bytes& value) {
    const int fd = ::memfd_create(
        "kpb-measurement-test-fixture", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    assert(fd >= 0);
    write_all(fd, value);
    return Fd(fd);
}

inline Fd open_runtime(const std::string& path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    assert(fd >= 0);
    return Fd(fd);
}

inline PublicMeasurementInputEndpoint::PublicLineage lineage(
        const RunBinding& binding, unsigned char seed) {
    return {
        .classification = binding.classification,
        .trial = binding.trial,
        .barrier = digest(static_cast<unsigned char>(seed + 2)),
        .capture_plan_identities = binding.round_capture_plans,
        .financial_runs = binding.financial_runs,
        .round_attempts = binding.round_attempts,
        .round_cohorts = binding.round_cohorts,
        .projections = binding.projections,
    };
}

inline MeasurementInputEndpointAuthority endpoint(
        MeasurementInputKind kind, unsigned owner, unsigned char seed,
        const PublicMeasurementInputEndpoint::PublicLineage& selected) {
    int pipe[2]{};
    assert(::pipe2(pipe, O_CLOEXEC) == 0);
    const unsigned char byte = seed;
    assert(::write(pipe[1], &byte, 1) == 1);
    ::close(pipe[1]);
    auto result = MeasurementInputEndpointAuthority::test_only_mint(
        kind, owner, pipe[0], digest(seed), selected,
        6000 + seed, digest(static_cast<unsigned char>(seed + 0x30)),
        digest(static_cast<unsigned char>(seed + 0x60)));
    ::close(pipe[0]);
    return result;
}

struct WorkerSet {
    WorkerBinding observer;
    WorkerBinding score;
    WorkerBinding aggregate;
    WorkerBinding comparison;
};

inline WorkerSet workers(const std::string& runtime_path) {
    const auto runtime = file_hash(runtime_path);
    const auto source = hash(archive(true));
    const auto assets = hash(archive(false));
    return {
        .observer = recompute_native_worker_binding(
            RuntimeChildRole::Observer, runtime, source, assets),
        .score = recompute_native_worker_binding(
            RuntimeChildRole::OwnerScore, runtime, source, assets),
        .aggregate = recompute_native_worker_binding(
            RuntimeChildRole::Aggregate, runtime, source, assets),
        .comparison = recompute_native_worker_binding(
            RuntimeChildRole::OwnerComparison, runtime, source, assets),
    };
}

inline MeasurementWorkerCapsuleAuthority capsule(
        const std::string& runtime_path, RuntimeChildRole role,
        unsigned owner,
        const PublicMeasurementInputEndpoint::PublicLineage& primary,
        const PublicMeasurementInputEndpoint::PublicLineage& secondary = {}) {
    auto runtime = open_runtime(runtime_path);
    auto source = memory_file(archive(true));
    auto assets = memory_file(archive(false));
    std::vector<MeasurementInputEndpointAuthority> inputs;
    switch (role) {
    case RuntimeChildRole::Observer:
        {
        auto observer = primary;
        observer.barrier = {};
        inputs.push_back(endpoint(
            MeasurementInputKind::ObserverCapture, NO_OWNER, 0x11,
            observer));
        }
        break;
    case RuntimeChildRole::OwnerScore:
        inputs.push_back(endpoint(
            MeasurementInputKind::ScoreObservation, NO_OWNER, 0x12, primary));
        inputs.push_back(endpoint(
            MeasurementInputKind::OwnerTruth, owner, 0x13, primary));
        break;
    case RuntimeChildRole::Aggregate:
        for (unsigned index = 0; index < 3; ++index)
            inputs.push_back(endpoint(
                MeasurementInputKind::AggregateOwnerScore, index,
                static_cast<unsigned char>(0x20 + index), primary));
        break;
    case RuntimeChildRole::OwnerComparison:
        for (unsigned index = 0; index < 3; ++index)
            inputs.push_back(endpoint(
                MeasurementInputKind::ComparisonBaselineOwnerScore, index,
                static_cast<unsigned char>(0x30 + index), primary));
        for (unsigned index = 0; index < 3; ++index)
            inputs.push_back(endpoint(
                MeasurementInputKind::ComparisonCandidateOwnerScore, index,
                static_cast<unsigned char>(0x40 + index), secondary));
        break;
    }
    return MeasurementWorkerCapsuleAuthority::seal_native(
        role, owner, runtime.get(), source.get(), assets.get(),
        std::move(inputs));
}

} // namespace kpb::measurement::runtime_bridge::test_fixture
