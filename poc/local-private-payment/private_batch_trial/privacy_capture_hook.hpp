#pragma once

#include <array>
#include <cstdint>
#include <exception>
#include <span>
#include <string>
#include <vector>

namespace kpb::capture {

struct RunBinding {
    std::string attempt_id;
    std::string cohort_sha256;
    std::string financial_run_id;
    std::string capture_identity;
    unsigned construction_classification{};
    std::string construction_attempt_sha256;
    std::string capture_plan_sha256;
};

struct Binding {
    std::string attempt_id;
    std::string cohort_sha256;
    std::string financial_run_id;
    std::string capture_identity;
    std::string projection_sha256;
    unsigned construction_classification{};
    std::string construction_attempt_sha256;
    std::string capture_plan_sha256;
};

struct ExplicitOwnerPublicEffect {
    unsigned owner_component{};
    std::string owner_contract_sha256;
    std::string nf_hex32;
    std::array<std::string, 2> tuple_sha256{};
};

struct ExplicitOwnerPublicEffects {
    std::string run_sha256;
    std::string trial_sha256;
    std::string attempt_sha256;
    std::string cohort_sha256;
    std::string capture_plan_sha256;
    std::string projection_sha256;
    std::string context_sha256;
    std::array<ExplicitOwnerPublicEffect, 3> owners{};
};

enum class ReleasePolicy {
    SecretPermutationIndependent,
    UploadOrderPublicEffects,
    ExplicitOwnerPublicEffects,
};

class CaptureRefused final : public std::exception {
public:
    const char* what() const noexcept override;
};

namespace detail {
class ProjectionChannel {
public:
    ProjectionChannel(int fd, unsigned round, const Binding& binding);
    ProjectionChannel(const ProjectionChannel&) = delete;
    ProjectionChannel& operator=(const ProjectionChannel&) = delete;
    ~ProjectionChannel();
    void write_and_close(std::span<const unsigned char> projection);
private:
    int fd_;
    bool complete_{};
    void frame(unsigned char tag, std::span<const unsigned char> payload);
    void close_complete();
};

class DispatcherChannel {
public:
    DispatcherChannel(int fd, unsigned round, ReleasePolicy policy,
                      const Binding& binding);
    DispatcherChannel(int fd, unsigned round, ReleasePolicy policy,
                      const RunBinding& binding);
    DispatcherChannel(const DispatcherChannel&) = delete;
    DispatcherChannel& operator=(const DispatcherChannel&) = delete;
    ~DispatcherChannel();
    void listeners_ready(std::uint64_t monotonic_ns);
    void owner_connected(unsigned owner, std::uint64_t monotonic_ns);
    void owner_upload_complete(unsigned owner, std::uint64_t monotonic_ns,
                               std::uint64_t bytes);
    void bind_projection(const std::string& projection_sha256);
    void aggregate_release(std::uint64_t monotonic_ns);
    void explicit_owner_public_effects(
        std::uint64_t monotonic_ns,
        const ExplicitOwnerPublicEffects& effects);
    void outbound_route(std::uint64_t monotonic_ns,
                        const std::string& route_sha256);
    void close_complete();
private:
    int fd_;
    unsigned round_;
    ReleasePolicy policy_;
    RunBinding binding_;
    std::string projection_sha256_;
    std::vector<std::string> pending_records_;
    std::uint64_t sequence_{};
    std::uint64_t prior_time_{};
    bool has_time_{};
    bool listeners_{};
    std::array<bool, 3> connected_{};
    std::array<bool, 3> uploaded_{};
    bool aggregate_{};
    bool explicit_effects_{};
    bool policy_bound_{};
    bool metadata_emitted_{};
    ExplicitOwnerPublicEffects effects_{};
    std::string explicit_event_sha256_;
    std::uint64_t outbound_{};
    bool complete_{};
    void frame(unsigned char tag, std::span<const unsigned char> payload);
    void emit_metadata();
    void bind_release_policy(std::uint64_t monotonic_ns);
    void record(const std::string& value);
    void event(const std::string& kind, int owner,
               const std::string& role, std::uint64_t monotonic_ns,
               std::uint64_t bytes, const std::string& filename,
               const std::string& public_sha256,
               const std::string& route_sha256);
};
} // namespace detail

template<int FixedFd, unsigned Round>
class ProjectionHook final {
    static_assert(FixedFd >= 20 && FixedFd <= 29);
    static_assert(Round == 1 || Round == 2);
public:
    explicit ProjectionHook(const Binding& binding)
        : channel_(FixedFd, Round, binding) {}
    void write_and_close(std::span<const unsigned char> projection) {
        channel_.write_and_close(projection);
    }
private:
    detail::ProjectionChannel channel_;
};

template<int FixedFd, unsigned Round, ReleasePolicy Policy>
class DispatcherHook final {
    static_assert(FixedFd >= 20 && FixedFd <= 29);
    static_assert(Round == 1 || Round == 2);
public:
    explicit DispatcherHook(const Binding& binding)
        : channel_(FixedFd, Round, Policy, binding) {}
    explicit DispatcherHook(const RunBinding& binding)
        : channel_(FixedFd, Round, Policy, binding) {}
    void listeners_ready(std::uint64_t time) {
        channel_.listeners_ready(time);
    }
    void owner_connected(unsigned owner, std::uint64_t time) {
        channel_.owner_connected(owner, time);
    }
    void owner_upload_complete(unsigned owner, std::uint64_t time,
                               std::uint64_t bytes) {
        channel_.owner_upload_complete(owner, time, bytes);
    }
    void bind_projection(const std::string& projection_sha256) {
        channel_.bind_projection(projection_sha256);
    }
    void aggregate_release(std::uint64_t time) {
        channel_.aggregate_release(time);
    }
    void explicit_owner_public_effects(
            std::uint64_t time,
            const ExplicitOwnerPublicEffects& effects) {
        channel_.explicit_owner_public_effects(time, effects);
    }
    void outbound_route(std::uint64_t time,
                        const std::string& route_sha256) {
        channel_.outbound_route(time, route_sha256);
    }
    void close_complete() { channel_.close_complete(); }
private:
    detail::DispatcherChannel channel_;
};

} // namespace kpb::capture
