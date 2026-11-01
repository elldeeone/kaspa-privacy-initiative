#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "privacy_measurement_worker_capsule.hpp"

#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <openssl/sha.h>
#include <span>
#include <sys/mman.h>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace kpb::measurement;
using namespace kpb::measurement::runtime_bridge;

namespace {

using Bytes = std::vector<unsigned char>;

template<class Function>
void refuses(Function&& function) {
    bool refused = false;
    try { function(); }
    catch (const Refused&) { refused = true; }
    assert(refused);
}

Digest digest(unsigned char value) {
    Digest result{};
    result.fill(value);
    return result;
}

void integer(Bytes& out, std::uint64_t value, unsigned width) {
    for (unsigned offset = 0; offset < width; ++offset)
        out.push_back(static_cast<unsigned char>(value >> (8 * offset)));
}

void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}

Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    assert(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return result;
}

void write_all(int fd, std::span<const unsigned char> value) {
    std::size_t at = 0;
    while (at < value.size()) {
        const auto count = ::write(fd, value.data() + at, value.size() - at);
        if (count < 0 && errno == EINTR) continue;
        assert(count > 0);
        at += static_cast<std::size_t>(count);
    }
}

int memfd(Bytes value) {
    const int fd = ::memfd_create(
        "kpb-capsule-control", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    assert(fd >= 0);
    write_all(fd, value);
    return fd;
}

Bytes archive(bool source, std::span<const unsigned char> content,
              std::span<const unsigned char> path =
                  std::span<const unsigned char>{}) {
    constexpr std::array<unsigned char, 8> source_magic{
        'K', 'P', 'B', 'S', 'R', 'C', '1', 0};
    constexpr std::array<unsigned char, 8> asset_magic{
        'K', 'P', 'B', 'A', 'S', 'T', '1', 0};
    constexpr std::array<unsigned char, 10> default_path{
        'w', 'o', 'r', 'k', 'e', 'r', '.', 'b', 'i', 'n'};
    if (path.empty()) path = default_path;
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

PublicMeasurementInputEndpoint::PublicLineage lineage(
        Classification classification, unsigned char seed) {
    return {
        .classification = classification,
        .trial = digest(seed),
        .barrier = digest(seed + 11),
        .capture_plan_identities = {digest(seed + 1), digest(seed + 2)},
        .financial_runs = {digest(seed + 3), digest(seed + 4)},
        .round_attempts = {digest(seed + 5), digest(seed + 6)},
        .round_cohorts = {digest(seed + 7), digest(seed + 8)},
        .projections = {digest(seed + 9), digest(seed + 10)},
    };
}

struct Pipe final {
    int read{-1};
    int write{-1};
    Pipe() {
        int pair[2]{};
        assert(::pipe2(pair, O_CLOEXEC) == 0);
        read = pair[0];
        write = pair[1];
    }
    Pipe(const Pipe&) = delete;
    Pipe& operator=(const Pipe&) = delete;
    ~Pipe() {
        if (read >= 0) ::close(read);
        if (write >= 0) ::close(write);
    }
};

MeasurementInputEndpointAuthority endpoint(
        MeasurementInputKind kind, unsigned owner, unsigned char seed,
        const PublicMeasurementInputEndpoint::PublicLineage& selected) {
    Pipe pipe;
    const unsigned char byte = seed;
    assert(::write(pipe.write, &byte, 1) == 1);
    ::close(std::exchange(pipe.write, -1));
    return MeasurementInputEndpointAuthority::test_only_mint(
        kind, owner, pipe.read, digest(seed), selected,
        4000 + seed, digest(seed + 0x40), digest(seed + 0x70));
}

struct CapsuleFiles final {
    int runtime{-1};
    int source{-1};
    int assets{-1};
    explicit CapsuleFiles(const char* runtime_path) {
        runtime = ::open(runtime_path, O_RDONLY | O_CLOEXEC);
        assert(runtime >= 0);
        source = memfd(archive(true, std::array<unsigned char, 3>{1, 2, 3}));
        assets = memfd(archive(false, std::array<unsigned char, 3>{4, 5, 6}));
    }
    CapsuleFiles(const CapsuleFiles&) = delete;
    CapsuleFiles& operator=(const CapsuleFiles&) = delete;
    ~CapsuleFiles() {
        if (runtime >= 0) ::close(runtime);
        if (source >= 0) ::close(source);
        if (assets >= 0) ::close(assets);
    }
};

std::vector<MeasurementInputEndpointAuthority> observer_inputs(
        const PublicMeasurementInputEndpoint::PublicLineage& selected) {
    std::vector<MeasurementInputEndpointAuthority> result;
    auto observer = selected;
    observer.barrier = {};
    result.push_back(endpoint(
        MeasurementInputKind::ObserverCapture, NO_OWNER, 0x11, observer));
    return result;
}

std::vector<MeasurementInputEndpointAuthority> score_inputs(
        unsigned owner,
        const PublicMeasurementInputEndpoint::PublicLineage& observation,
        const PublicMeasurementInputEndpoint::PublicLineage& truth) {
    std::vector<MeasurementInputEndpointAuthority> result;
    result.push_back(endpoint(
        MeasurementInputKind::ScoreObservation, NO_OWNER, 0x12,
        observation));
    result.push_back(endpoint(
        MeasurementInputKind::OwnerTruth, owner, 0x13, truth));
    return result;
}

std::vector<MeasurementInputEndpointAuthority> aggregate_inputs(
        const PublicMeasurementInputEndpoint::PublicLineage& selected) {
    std::vector<MeasurementInputEndpointAuthority> result;
    for (unsigned owner = 0; owner < 3; ++owner)
        result.push_back(endpoint(
            MeasurementInputKind::AggregateOwnerScore, owner,
            static_cast<unsigned char>(0x18 + owner), selected));
    return result;
}

std::vector<MeasurementInputEndpointAuthority> comparison_inputs(
        const PublicMeasurementInputEndpoint::PublicLineage& baseline,
        const PublicMeasurementInputEndpoint::PublicLineage& candidate) {
    std::vector<MeasurementInputEndpointAuthority> result;
    for (unsigned owner = 0; owner < 3; ++owner)
        result.push_back(endpoint(
            MeasurementInputKind::ComparisonBaselineOwnerScore, owner,
            static_cast<unsigned char>(0x28 + owner), baseline));
    for (unsigned owner = 0; owner < 3; ++owner)
        result.push_back(endpoint(
            MeasurementInputKind::ComparisonCandidateOwnerScore, owner,
            static_cast<unsigned char>(0x38 + owner), candidate));
    return result;
}

void valid_capsules_are_sealed(const char* runtime_path) {
    CapsuleFiles files(runtime_path);
    const auto selected = lineage(Classification::TransparentBaseline, 0x21);
    auto capsule = MeasurementWorkerCapsuleAuthority::seal_native(
        RuntimeChildRole::Observer, NO_OWNER, files.runtime, files.source,
        files.assets, observer_inputs(selected));
    capsule.test_only_verify_seals_and_read_only();
    assert(capsule.public_receipt().role == RuntimeChildRole::Observer);
    assert(capsule.public_receipt().input_count == 1);
    assert(capsule.public_receipt().capsule_identity != Digest{});
    {
        CapsuleFiles aggregate_files(runtime_path);
        auto aggregate = MeasurementWorkerCapsuleAuthority::seal_native(
            RuntimeChildRole::Aggregate, NO_OWNER, aggregate_files.runtime,
            aggregate_files.source, aggregate_files.assets,
            aggregate_inputs(selected));
        aggregate.test_only_verify_seals_and_read_only();
        assert(aggregate.public_receipt().input_count == 3);
    }
    {
        CapsuleFiles comparison_files(runtime_path);
        const auto candidate = lineage(
            Classification::HiddenCandidate, 0x51);
        auto comparison = MeasurementWorkerCapsuleAuthority::seal_native(
            RuntimeChildRole::OwnerComparison, NO_OWNER,
            comparison_files.runtime, comparison_files.source,
            comparison_files.assets,
            comparison_inputs(selected, candidate));
        comparison.test_only_verify_seals_and_read_only();
        assert(comparison.public_receipt().input_count == 6);
    }
}

void wrong_role_owner_lineage_alias_and_replay_refuse(
        const char* runtime_path) {
    const auto baseline = lineage(
        Classification::TransparentBaseline, 0x21);
    {
        CapsuleFiles files(runtime_path);
        refuses([&] {
            (void)MeasurementWorkerCapsuleAuthority::seal_native(
                RuntimeChildRole::OwnerScore, 1, files.runtime,
                files.source, files.assets, observer_inputs(baseline));
        });
    }
    {
        CapsuleFiles files(runtime_path);
        refuses([&] {
            (void)MeasurementWorkerCapsuleAuthority::seal_native(
                RuntimeChildRole::OwnerScore, 1, files.runtime,
                files.source, files.assets,
                score_inputs(2, baseline, baseline));
        });
    }
    {
        CapsuleFiles files(runtime_path);
        auto wrong = baseline;
        wrong.projections[1] = digest(0xee);
        refuses([&] {
            (void)MeasurementWorkerCapsuleAuthority::seal_native(
                RuntimeChildRole::OwnerScore, 1, files.runtime,
                files.source, files.assets,
                score_inputs(1, baseline, wrong));
        });
    }
    {
        std::vector<PublicMeasurementInputEndpoint::PublicLineage> wrong;
        auto value = baseline;
        value.classification = Classification::HiddenCandidate;
        wrong.push_back(value);
        value = baseline; value.trial = digest(0xe1); wrong.push_back(value);
        value = baseline; value.capture_plan_identities[0] = digest(0xe2);
        wrong.push_back(value);
        value = baseline; value.financial_runs[1] = digest(0xe3);
        wrong.push_back(value);
        value = baseline; value.round_attempts[0] = digest(0xe4);
        wrong.push_back(value);
        value = baseline; value.round_cohorts[1] = digest(0xe5);
        wrong.push_back(value);
        for (const auto& changed : wrong) {
            CapsuleFiles files(runtime_path);
            refuses([&] {
                (void)MeasurementWorkerCapsuleAuthority::seal_native(
                    RuntimeChildRole::OwnerScore, 1, files.runtime,
                    files.source, files.assets,
                    score_inputs(1, baseline, changed));
            });
        }
    }
    {
        auto reused = baseline;
        reused.financial_runs[1] = reused.financial_runs[0];
        refuses([&] {
            (void)score_inputs(1, baseline, reused);
        });
    }
    {
        CapsuleFiles files(runtime_path);
        std::vector<MeasurementInputEndpointAuthority> inputs;
        inputs.push_back(endpoint(
            MeasurementInputKind::OwnerTruth, 1, 0x14, baseline));
        refuses([&] {
            (void)MeasurementWorkerCapsuleAuthority::seal_native(
                RuntimeChildRole::Observer, NO_OWNER, files.runtime,
                files.source, files.assets, std::move(inputs));
        });
    }
    {
        CapsuleFiles files(runtime_path);
        Pipe shared;
        const unsigned char byte = 1;
        assert(::write(shared.write, &byte, 1) == 1);
        ::close(std::exchange(shared.write, -1));
        std::vector<MeasurementInputEndpointAuthority> inputs;
        inputs.push_back(MeasurementInputEndpointAuthority::test_only_mint(
            MeasurementInputKind::ScoreObservation, NO_OWNER, shared.read,
            digest(0x31), baseline, 5101, digest(0x41), digest(0x51)));
        inputs.push_back(MeasurementInputEndpointAuthority::test_only_mint(
            MeasurementInputKind::OwnerTruth, 1, shared.read,
            digest(0x32), baseline, 5102, digest(0x42), digest(0x52)));
        refuses([&] {
            (void)MeasurementWorkerCapsuleAuthority::seal_native(
                RuntimeChildRole::OwnerScore, 1, files.runtime,
                files.source, files.assets, std::move(inputs));
        });
    }
    {
        CapsuleFiles files(runtime_path);
        auto inputs = observer_inputs(baseline);
        auto capsule = MeasurementWorkerCapsuleAuthority::seal_native(
            RuntimeChildRole::Observer, NO_OWNER, files.runtime,
            files.source, files.assets, std::move(inputs));
        (void)capsule;
        refuses([&] {
            (void)MeasurementWorkerCapsuleAuthority::seal_native(
                RuntimeChildRole::Observer, NO_OWNER, files.runtime,
                files.source, files.assets, std::move(inputs));
        });
    }
}

void wrong_runtime_archive_and_writable_input_refuse(
        const char* runtime_path, const char* dynamic_path) {
    const auto baseline = lineage(
        Classification::TransparentBaseline, 0x21);
    {
        CapsuleFiles files(runtime_path);
        const int dynamic = ::open(dynamic_path, O_RDONLY | O_CLOEXEC);
        assert(dynamic >= 0);
        refuses([&] {
            (void)MeasurementWorkerCapsuleAuthority::seal_native(
                RuntimeChildRole::Observer, NO_OWNER, dynamic,
                files.source, files.assets, observer_inputs(baseline));
        });
        ::close(dynamic);
    }
    {
        CapsuleFiles files(runtime_path);
        auto broken = archive(false, std::array<unsigned char, 3>{4, 5, 6});
        broken[broken.size() - 1] ^= 1;
        const int bad_assets = memfd(std::move(broken));
        refuses([&] {
            (void)MeasurementWorkerCapsuleAuthority::seal_native(
                RuntimeChildRole::Observer, NO_OWNER, files.runtime,
                files.source, bad_assets, observer_inputs(baseline));
        });
        ::close(bad_assets);
    }
    {
        const int writable = memfd(Bytes{1, 2, 3});
        refuses([&] {
            (void)MeasurementInputEndpointAuthority::test_only_mint(
                MeasurementInputKind::ObserverCapture, NO_OWNER, writable,
                digest(0x30), baseline, 5201, digest(0x40), digest(0x50));
        });
        ::close(writable);
    }
}

} // namespace

int main(int argc, char** argv) {
    assert(argc == 3);
    valid_capsules_are_sealed(argv[1]);
    wrong_role_owner_lineage_alias_and_replay_refuse(argv[1]);
    wrong_runtime_archive_and_writable_input_refuse(argv[1], argv[2]);
}
