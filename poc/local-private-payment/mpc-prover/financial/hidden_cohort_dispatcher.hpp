#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace kpi::mpc::financial::hidden_cohort {

using Digest = std::array<unsigned char, 32>;

inline constexpr std::string_view COMMON_INGRESS_ROUTE =
    "REGISTERED_COMMON_OWNER_INGRESS";
inline constexpr std::string_view COMMON_AGGREGATE_ROUTE =
    "ONE_UNLABELLED_PUBLIC_AGGREGATE";

class Refused final : public std::runtime_error {
public:
    Refused() : std::runtime_error("hidden-cohort-dispatcher-refused") {}
};

struct PrivatePermutationEvidence {
    std::string model;
    std::string source;
    std::string trace;
    std::string layout;
    std::string recipe;
    std::size_t random_bits{};
    std::size_t input_rows{};
    std::size_t output_rows{};
    bool nf_sort_private{};
    bool output_sort_private{};
    bool dispatcher_chosen{};
};

struct Selection {
    Digest attempt{};
    Digest cohort{};
    std::array<Digest, 3> owner_certificates{};
    std::size_t masked_frame_bytes{};
    PrivatePermutationEvidence permutation;
};

struct Ingress {
    int owner_role{-1};
    Digest owner_certificate{};
    Digest attempt{};
    Digest cohort{};
    std::uint64_t connection_ordinal{};
    std::uint64_t attempt_ordinal{};
    std::string route;
    bool retry{};
    std::vector<unsigned char> opaque_masked_frame;
};

struct PublicCapture {
    Digest attempt{};
    Digest cohort{};
    std::vector<int> connection_order;
    std::vector<int> upload_order;
    std::vector<std::size_t> observed_lengths;
    std::string ingress_route;
    bool owner_mapping_exported{};
    bool public_slot_association_exported{};
    bool filenames_exported{};
    std::size_t per_owner_release_routes{};
};

struct AggregateRelease {
    Digest aggregate_identity{};
    std::string route;
    std::string invariant_identity;
    std::size_t release_count{};
    bool owner_mapping_exported{};
};

struct SourceStatus {
    std::string schema;
    std::string status;
    bool authenticated_mpc_integration{};
    bool registered_driver_integration{};
    bool launch_authorized{};
    bool privacy_qualified{};
};

class Dispatcher;

class SealedCohort final {
    friend class Dispatcher;

    Selection selection_;
    std::array<std::vector<unsigned char>, 3> by_role_;
    PublicCapture capture_;
    bool released_{};

    SealedCohort(Selection, std::array<std::vector<unsigned char>, 3>,
                 PublicCapture);
public:
    SealedCohort(const SealedCohort&) = delete;
    SealedCohort& operator=(const SealedCohort&) = delete;
    SealedCohort(SealedCohort&&) noexcept = default;
    SealedCohort& operator=(SealedCohort&&) noexcept = default;

    const PublicCapture& capture() const noexcept { return capture_; }
    AggregateRelease release_unlabelled_aggregate(const Digest& aggregate_identity);
};

class Dispatcher final {
    Selection selection_;
    std::array<std::optional<std::vector<unsigned char>>, 3> by_role_;
    PublicCapture capture_;
    bool sealed_{};
public:
    explicit Dispatcher(Selection);
    void admit(Ingress);
    SealedCohort seal();
};

SourceStatus source_status();

} // namespace kpi::mpc::financial::hidden_cohort
