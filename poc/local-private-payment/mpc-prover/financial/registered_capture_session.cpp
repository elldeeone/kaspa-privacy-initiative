#include "registered_capture_session.hpp"
#include "baseline_public_effects_collector.hpp"

#include "../../private_batch_trial/privacy_capture_hook.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>
#include <time.h>
#include <utility>

namespace kpi::mpc::financial::registered_driver {
namespace {

using kpb::capture::Binding;
using kpb::capture::DispatcherHook;
using kpb::capture::ProjectionHook;
using kpb::capture::ReleasePolicy;
using kpb::capture::RunBinding;

[[noreturn]] void refuse() {
    throw std::runtime_error("registered-capture-session-refused");
}

void need(bool value) { if (!value) refuse(); }

std::uint64_t monotonic_ns() {
    timespec value{};
    need(::clock_gettime(CLOCK_MONOTONIC, &value) == 0 &&
         value.tv_sec >= 0 && value.tv_nsec >= 0 &&
         value.tv_nsec < 1000000000L &&
         static_cast<std::uint64_t>(value.tv_sec) <=
             std::numeric_limits<std::uint64_t>::max() / 1000000000ULL);
    return static_cast<std::uint64_t>(value.tv_sec) * 1000000000ULL +
           static_cast<std::uint64_t>(value.tv_nsec);
}

class Dispatcher {
public:
    virtual ~Dispatcher() = default;
    virtual void listeners_ready(std::uint64_t) = 0;
    virtual void owner_connected(unsigned, std::uint64_t) = 0;
    virtual void owner_upload_complete(unsigned, std::uint64_t,
                                       std::uint64_t) = 0;
    virtual void bind_projection(const std::string&) = 0;
    virtual void aggregate_release(std::uint64_t) = 0;
    virtual void explicit_owner_public_effects(
        std::uint64_t, const kpb::capture::ExplicitOwnerPublicEffects&) = 0;
    virtual void outbound_route(std::uint64_t, const std::string&) = 0;
    virtual void close_complete() = 0;
};

template<int FixedFd, unsigned Round, ReleasePolicy Policy>
class FixedDispatcher final : public Dispatcher {
    DispatcherHook<FixedFd, Round,
        Policy> hook_;
public:
    explicit FixedDispatcher(const RunBinding& binding) : hook_(binding) {}
    void listeners_ready(std::uint64_t time) override {
        hook_.listeners_ready(time);
    }
    void owner_connected(unsigned owner, std::uint64_t time) override {
        hook_.owner_connected(owner, time);
    }
    void owner_upload_complete(unsigned owner, std::uint64_t time,
                               std::uint64_t bytes) override {
        hook_.owner_upload_complete(owner, time, bytes);
    }
    void bind_projection(const std::string& identity) override {
        hook_.bind_projection(identity);
    }
    void aggregate_release(std::uint64_t time) override {
        hook_.aggregate_release(time);
    }
    void explicit_owner_public_effects(
            std::uint64_t time,
            const kpb::capture::ExplicitOwnerPublicEffects& effects) override {
        hook_.explicit_owner_public_effects(time, effects);
    }
    void outbound_route(std::uint64_t time,
                        const std::string& route) override {
        hook_.outbound_route(time, route);
    }
    void close_complete() override { hook_.close_complete(); }
};

void capture_projection(unsigned round, const Binding& binding,
                        std::span<const unsigned char> projection) {
    if (round == 1) {
        ProjectionHook<20, 1> hook(binding);
        hook.write_and_close(projection);
    } else if (round == 2) {
        ProjectionHook<25, 2> hook(binding);
        hook.write_and_close(projection);
    } else {
        refuse();
    }
}

} // namespace

class RegisteredCaptureSession::Impl final {
public:
    const PublicCapturePlan plan;
    const Digest plan_identity;
    const RunBinding run_binding;
    std::unique_ptr<Dispatcher> dispatcher;
    Digest projection{};
    std::array<std::byte, 10685> projection_bytes{};
    unsigned computing_role{};
    bool listeners{};
    bool released{};
    bool explicit_effects{};
    bool route_complete{};

    Impl(PublicCapturePlan selected, Digest identity, unsigned role)
        : plan(std::move(selected)), plan_identity(identity),
          run_binding{plan.capture_attempt_id,
                      identity_registry::hex(plan.cohort),
                      identity_registry::hex(plan.run),
                      plan.capture_identity,
                      static_cast<unsigned>(plan.classification),
                      identity_registry::hex(plan.attempt),
                      identity_registry::hex(plan_identity)},
          computing_role(role) {
        constexpr std::array<int, 10> expected{
            20, 21, 22, 23, 24, 25, 26, 27, 28, 29};
        need((plan.round == 1 || plan.round == 2) && role < 3 &&
             plan.fixed_fds == expected && plan_identity != Digest{});
        if (role == CAPTURE_STREAM_OWNER_ROLE) {
            if (plan.round == 1) {
                if (plan.classification ==
                        CaptureClassification::ExplicitOwnerPublicEffectsBaseline)
                    dispatcher = std::make_unique<FixedDispatcher<22, 1,
                        ReleasePolicy::ExplicitOwnerPublicEffects>>(run_binding);
                else
                    dispatcher = std::make_unique<FixedDispatcher<22, 1,
                        ReleasePolicy::SecretPermutationIndependent>>(run_binding);
            } else {
                if (plan.classification ==
                        CaptureClassification::ExplicitOwnerPublicEffectsBaseline)
                    dispatcher = std::make_unique<FixedDispatcher<27, 2,
                        ReleasePolicy::ExplicitOwnerPublicEffects>>(run_binding);
                else
                    dispatcher = std::make_unique<FixedDispatcher<27, 2,
                        ReleasePolicy::SecretPermutationIndependent>>(run_binding);
            }
        }
    }
};

RegisteredCaptureSession::RegisteredCaptureSession(
        CapturePlanAuthority&& authority, unsigned computing_role) {
    auto consumed = CapturePlanAuthorityBridge::consume_session(
        std::move(authority), computing_role);
    impl_ = std::make_unique<Impl>(std::move(consumed.value),
                                   consumed.identity, computing_role);
}

std::unique_ptr<RegisteredCaptureSession> RegisteredCaptureSession::begin(
        CapturePlanAuthority&& authority, unsigned computing_role) {
    return std::unique_ptr<RegisteredCaptureSession>(
        new RegisteredCaptureSession(std::move(authority), computing_role));
}

RegisteredCaptureSession::~RegisteredCaptureSession() = default;

void RegisteredCaptureConstructionBridge::listeners_ready(
        RegisteredCaptureSession& session) {
    session.listeners_ready();
}

void RegisteredCaptureEgressBridge::released_projection(
        RegisteredCaptureSession& session,
        std::span<const unsigned char> projection) {
    session.released_projection(projection);
}

baseline_disclosure::BaselineTerminalOwnerMappingAuthority
RegisteredBaselineObserverCaptureBridge::explicit_owner_public_effects(
        RegisteredCaptureSession& session,
        baseline_disclosure::ExplicitOwnerPublicEffectsAuthority&& authority) {
    return session.explicit_owner_public_effects(std::move(authority));
}

void RegisteredCaptureSession::listeners_ready() {
    need(impl_ && !impl_->listeners && !impl_->released);
    if (impl_->dispatcher) impl_->dispatcher->listeners_ready(monotonic_ns());
    impl_->listeners = true;
}

void RegisteredCaptureSession::owner_authenticated(unsigned owner) {
    need(impl_ && impl_->listeners && !impl_->released);
    if (impl_->dispatcher)
        impl_->dispatcher->owner_connected(owner, monotonic_ns());
}

void RegisteredCaptureSession::owner_upload_complete(
        unsigned owner, std::size_t fixed_frame_bytes) {
    need(impl_ && impl_->listeners && !impl_->released &&
         fixed_frame_bytes <= std::numeric_limits<std::uint64_t>::max());
    if (impl_->dispatcher)
        impl_->dispatcher->owner_upload_complete(
            owner, monotonic_ns(),
            static_cast<std::uint64_t>(fixed_frame_bytes));
}

void RegisteredCaptureSession::released_projection(
        std::span<const unsigned char> projection) {
    need(impl_ && impl_->listeners && !impl_->released &&
         projection.size() == 10685);
    const auto projection_identity = identity_registry::digest(projection);
    const auto projection_hex = identity_registry::hex(projection_identity);
    if (impl_->dispatcher) {
        const Binding binding{
            impl_->run_binding.attempt_id,
            impl_->run_binding.cohort_sha256,
            impl_->run_binding.financial_run_id,
            impl_->run_binding.capture_identity,
            projection_hex,
            impl_->run_binding.construction_classification,
            impl_->run_binding.construction_attempt_sha256,
            impl_->run_binding.capture_plan_sha256,
        };
        // Exact bytes come from the fully constructed durable-EGRESS object.
        // The dispatcher records one aggregate release. Only the private
        // projection-route bridge may later emit outbound-route and END after
        // the parent has read the exact retained bytes, observed EOF and ACKed.
        capture_projection(impl_->plan.round, binding, projection);
        impl_->dispatcher->bind_projection(projection_hex);
        impl_->dispatcher->aggregate_release(monotonic_ns());
    }
    impl_->projection = projection_identity;
    std::transform(
        projection.begin(), projection.end(), impl_->projection_bytes.begin(),
        [](unsigned char value) { return static_cast<std::byte>(value); });
    impl_->released = true;
}

baseline_disclosure::BaselineTerminalOwnerMappingAuthority
RegisteredCaptureSession::explicit_owner_public_effects(
        baseline_disclosure::ExplicitOwnerPublicEffectsAuthority&& authority) {
    using kpb::capture::ExplicitOwnerPublicEffect;
    using HookEffects = kpb::capture::ExplicitOwnerPublicEffects;
    need(impl_ && impl_->computing_role == CAPTURE_STREAM_OWNER_ROLE &&
         impl_->dispatcher && impl_->released && !impl_->explicit_effects &&
         impl_->plan.classification ==
             CaptureClassification::ExplicitOwnerPublicEffectsBaseline);
    const auto value = authority.consume_for_capture();
    need(value.status == "EXPLICIT_OWNER_PUBLIC_EFFECTS" &&
         value.classification == impl_->plan.classification &&
         value.round == impl_->plan.round && value.run == impl_->plan.run &&
         value.attempt == impl_->plan.attempt &&
         value.cohort == impl_->plan.cohort &&
         value.capture_plan_identity == impl_->plan_identity &&
         value.projection_identity == impl_->projection &&
         value.trial == impl_->plan.trial &&
         value.context_identity != Digest{});
    HookEffects effects{
        .run_sha256 = identity_registry::hex(value.run),
        .trial_sha256 = identity_registry::hex(value.trial),
        .attempt_sha256 = identity_registry::hex(value.attempt),
        .cohort_sha256 = identity_registry::hex(value.cohort),
        .capture_plan_sha256 =
            identity_registry::hex(value.capture_plan_identity),
        .projection_sha256 = identity_registry::hex(value.projection_identity),
        .context_sha256 = identity_registry::hex(value.context_identity),
    };
    for (unsigned owner = 0; owner < effects.owners.size(); ++owner) {
        const auto& source = value.owner_effects[owner];
        need(source.owner == owner &&
             source.owner_contract_identity != Digest{} &&
             source.public_nullifier != Digest{} &&
             source.public_tuple_hashes[0] <
                 source.public_tuple_hashes[1]);
        effects.owners[owner] = ExplicitOwnerPublicEffect{
            .owner_component = owner,
            .owner_contract_sha256 =
                identity_registry::hex(source.owner_contract_identity),
            .nf_hex32 = identity_registry::hex(source.public_nullifier),
            .tuple_sha256 = {
                identity_registry::hex(source.public_tuple_hashes[0]),
                identity_registry::hex(source.public_tuple_hashes[1]),
            },
        };
    }
    impl_->dispatcher->explicit_owner_public_effects(monotonic_ns(), effects);
    impl_->explicit_effects = true;
    return baseline_disclosure::BaselineTerminalOwnerMappingAuthority(
        std::move(value));
}

const Digest& RegisteredCaptureSession::plan_identity() const {
    need(static_cast<bool>(impl_)); return impl_->plan_identity;
}

const Digest& RegisteredCaptureSession::projection_identity() const {
    need(impl_ && impl_->released); return impl_->projection;
}

void RegisteredCaptureSession::require_baseline_effects_ready() const {
    need(impl_ && impl_->released && !impl_->route_complete &&
         impl_->plan.classification ==
             CaptureClassification::ExplicitOwnerPublicEffectsBaseline);
}

void RegisteredCaptureSession::require_egress_completion_ready() const {
    need(impl_ && impl_->released &&
         (impl_->computing_role != CAPTURE_STREAM_OWNER_ROLE ||
          impl_->route_complete));
}

const PublicCapturePlan& RegisteredCaptureSession::route_capture_plan() const {
    need(impl_ && impl_->computing_role == CAPTURE_STREAM_OWNER_ROLE &&
         impl_->released && !impl_->route_complete);
    return impl_->plan;
}

const std::array<std::byte, 10685>&
RegisteredCaptureSession::retained_projection_for_route() const {
    need(impl_ && impl_->computing_role == CAPTURE_STREAM_OWNER_ROLE &&
         impl_->released && !impl_->route_complete);
    return impl_->projection_bytes;
}

void RegisteredCaptureSession::close_after_projection_route(
        const Digest& route_identity, const Digest& projection_identity) {
    need(impl_ && impl_->computing_role == CAPTURE_STREAM_OWNER_ROLE &&
         impl_->dispatcher && impl_->released && !impl_->route_complete &&
         route_identity != Digest{} && projection_identity == impl_->projection &&
         ((impl_->plan.classification ==
               CaptureClassification::ExplicitOwnerPublicEffectsBaseline &&
           impl_->explicit_effects) ||
          (impl_->plan.classification ==
               CaptureClassification::HiddenCandidate &&
           !impl_->explicit_effects)));
    impl_->dispatcher->outbound_route(
        monotonic_ns(), identity_registry::hex(route_identity));
    impl_->dispatcher->close_complete();
    std::fill(impl_->projection_bytes.begin(),
              impl_->projection_bytes.end(), std::byte{});
    impl_->route_complete = true;
}

#ifdef KPI_REGISTERED_CAPTURE_SESSION_TEST_SETUP
void RegisteredCaptureSession::test_only_corrupt_retained_projection() {
    need(impl_ && impl_->released && !impl_->route_complete);
    impl_->projection_bytes[0] ^= std::byte{1};
}

void RegisteredCaptureSession::test_only_corrupt_projection_identity() {
    need(impl_ && impl_->released && !impl_->route_complete);
    impl_->projection[0] ^= 1;
}

bool RegisteredCaptureSession::test_only_route_complete() const {
    return impl_ && impl_->route_complete;
}
#endif

} // namespace kpi::mpc::financial::registered_driver
