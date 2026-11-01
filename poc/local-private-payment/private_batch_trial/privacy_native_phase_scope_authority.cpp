#include "privacy_native_phase_scope_authority.hpp"

#include "privacy_measurement_child_output_authority.hpp"
#include "privacy_measurement_output_abi.hpp"
#include "privacy_native_empirical_result_authority.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <span>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>
#include <utility>

namespace kpb::measurement::phase_scope {
namespace {

using empirical_result::NativeEmpiricalResultAuthority;
using runtime_bridge::OBSERVER_OUTPUT_ABI;
using runtime_bridge::OBSERVER_PHASE_V2_BYTES;
using runtime_bridge::OBSERVER_PHASE_V2_OFFSET;
using runtime_bridge::OBSERVER_STEP2_DEFERRED_STEP3_COUNTS;
using runtime_bridge::OBSERVER_STEP2_EMPIRICAL_OPEN_MASK;
using runtime_bridge::OBSERVER_STEP2_FAMILY_ROWS;
using runtime_bridge::OBSERVER_STEP2_MODEL_IDENTITY;
using runtime_bridge::OBSERVER_STEP2_REGISTRY_IDENTITY;
using runtime_bridge::OBSERVER_STEP2_V3_BYTES;
using runtime_bridge::OBSERVER_STEP2_V3_OFFSET;
using runtime_bridge::OBSERVER_STEP2_VIEW_TOTALS;
using runtime_bridge::PrivateChildOutputCompletion;
using runtime_bridge::RuntimeChildRole;
using runtime_bridge::SealedChildOutputAuthority;

[[noreturn]] void refuse() { throw Refused(); }
void need(bool value) { if (!value) refuse(); }

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

struct PrivatePhaseBinding {
    PrivateChildOutputCompletion completion;
    Digest sealed_output_identity{};

    PrivatePhaseBinding(
            PrivateChildOutputCompletion supplied_completion,
            Digest supplied_identity)
        : completion(std::move(supplied_completion)),
          sealed_output_identity(std::move(supplied_identity)) {}
    PrivatePhaseBinding(const PrivatePhaseBinding&) = delete;
    PrivatePhaseBinding& operator=(const PrivatePhaseBinding&) = delete;
    PrivatePhaseBinding(PrivatePhaseBinding&& other) noexcept
        : completion(other.completion),
          sealed_output_identity(other.sealed_output_identity) {
        other.cleanse();
    }
    PrivatePhaseBinding& operator=(PrivatePhaseBinding&&) = delete;
    ~PrivatePhaseBinding() { cleanse(); }

private:
    void cleanse() noexcept {
        static_assert(std::is_trivially_copyable_v<
                      PrivateChildOutputCompletion>);
        OPENSSL_cleanse(&completion, sizeof(completion));
        OPENSSL_cleanse(sealed_output_identity.data(),
                        sealed_output_identity.size());
    }
};

void read_exact(int fd, std::span<unsigned char> target, off_t offset) {
    std::size_t at = 0;
    while (at < target.size()) {
        ssize_t amount;
        do {
            amount = ::pread(fd, target.data() + at, target.size() - at,
                             offset + static_cast<off_t>(at));
        } while (amount < 0 && errno == EINTR);
        need(amount > 0);
        at += static_cast<std::size_t>(amount);
    }
}

unsigned u16be(std::span<const unsigned char> value) {
    need(value.size() == 2);
    return static_cast<unsigned>(value[0]) << 8U | value[1];
}

void validate_completion(
        const PrivateChildOutputCompletion& completion,
        const Digest& sealed_identity) {
    validate_measurement_run_binding(completion.offer.binding);
    need(OBSERVER_OUTPUT_ABI.version == 3 &&
         completion.offer.role == RuntimeChildRole::Observer &&
         completion.offer.owner == runtime_bridge::NO_OWNER &&
         completion.offer.worker == completion.offer.binding.observer_worker &&
         completion.offer.output_abi_identity == OBSERVER_OUTPUT_ABI.identity &&
         completion.offer.exact_size == OBSERVER_OUTPUT_ABI.exact_bytes &&
         nonzero(completion.offer.permit_identity) &&
         nonzero(completion.offer.transport_session) &&
         nonzero(completion.offer.output_authority_identity) &&
         nonzero(completion.content_hash) &&
         nonzero(completion.process_identity) &&
         nonzero(completion.child_exit_identity) &&
         nonzero(sealed_identity) &&
         completion.process_identity != completion.child_exit_identity &&
         completion.authenticated_pid > 1 &&
         completion.waited_pid == completion.authenticated_pid &&
         completion.exit_code == 0 && completion.term_signal == 0 &&
         completion.credentials_verified && completion.eof_observed);
}

void validate_sealed_fd(int fd) {
    struct stat selected{};
    constexpr int required_seals =
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    const int descriptor_flags = ::fcntl(fd, F_GETFL);
    const int descriptor_seals = ::fcntl(fd, F_GET_SEALS);
    need(fd >= 0 && ::fstat(fd, &selected) == 0 &&
         S_ISREG(selected.st_mode) &&
         static_cast<std::uint64_t>(selected.st_size) ==
             OBSERVER_OUTPUT_ABI.exact_bytes &&
         descriptor_flags >= 0 &&
         (descriptor_flags & O_ACCMODE) == O_RDONLY &&
         descriptor_seals >= 0 &&
         (descriptor_seals & required_seals) == required_seals);
}

// ABI v3 is an immutable inventory of unresolved Step-2 work, not
// authorization. Recheck every fixed field before retaining it so a forged
// zero-count/CLOSED/mask section can never be reinterpreted as a permit.
void validate_exact_open_inventory(
        std::span<const unsigned char> value) {
    need(value.size() == OBSERVER_STEP2_V3_BYTES &&
         runtime_bridge::validate_observer_step2_v3_section(value));
    std::size_t at = 20;
    for (const auto total : OBSERVER_STEP2_VIEW_TOTALS) {
        need(total > 0 && u16be(value.subspan(at, 2)) == total);
        at += 2;
    }
    for (const auto deferred : OBSERVER_STEP2_DEFERRED_STEP3_COUNTS)
        need(deferred == 4 && value[at++] == deferred);
    need(std::equal(OBSERVER_STEP2_REGISTRY_IDENTITY.begin(),
                    OBSERVER_STEP2_REGISTRY_IDENTITY.end(),
                    value.begin() + static_cast<std::ptrdiff_t>(at)));
    at += OBSERVER_STEP2_REGISTRY_IDENTITY.size();
    need(std::equal(OBSERVER_STEP2_MODEL_IDENTITY.begin(),
                    OBSERVER_STEP2_MODEL_IDENTITY.end(),
                    value.begin() + static_cast<std::ptrdiff_t>(at)));
    at += OBSERVER_STEP2_MODEL_IDENTITY.size();
    for (const auto& row : OBSERVER_STEP2_FAMILY_ROWS) {
        need(value[at++] == row.code);
        bool row_open = false;
        for (const auto count : row.counts) {
            need(value[at++] == count);
            row_open = row_open || count != 0;
        }
        need(row_open && value[at++] ==
            static_cast<unsigned char>(row.disposition));
    }
    need(u16be(value.subspan(at, 2)) ==
             OBSERVER_STEP2_EMPIRICAL_OPEN_MASK &&
         OBSERVER_STEP2_EMPIRICAL_OPEN_MASK != 0);
    at += 2;
    need(u16be(value.subspan(at, 2)) == 0);
    at += 2;
    need(at == value.size());
}

} // namespace

struct ObservationOutputJoinAuthority::Storage {
    PrivatePhaseBinding binding;
    SealedChildOutputAuthority output;
    NativeEmpiricalResultAuthority empirical;
    std::array<unsigned char, OBSERVER_PHASE_V2_BYTES> deferred_step3{};
    std::array<unsigned char, OBSERVER_STEP2_V3_BYTES> open_step2{};

    Storage(PrivatePhaseBinding&& supplied_binding,
            SealedChildOutputAuthority&& supplied_output,
            NativeEmpiricalResultAuthority&& supplied_empirical,
            std::array<unsigned char, OBSERVER_PHASE_V2_BYTES> supplied_phase,
            std::array<unsigned char, OBSERVER_STEP2_V3_BYTES> supplied_step2)
        : binding(std::move(supplied_binding)),
          output(std::move(supplied_output)),
          empirical(std::move(supplied_empirical)),
          deferred_step3(std::move(supplied_phase)),
          open_step2(std::move(supplied_step2)) {}

    ~Storage() {
        OPENSSL_cleanse(deferred_step3.data(), deferred_step3.size());
        OPENSSL_cleanse(open_step2.data(), open_step2.size());
    }
};

ObservationOutputFanoutTransfer::ObservationOutputFanoutTransfer(
        void* storage, void (*destroy)(void*) noexcept,
        const PrivateChildOutputCompletion* completion,
        const Digest* sealed_output_identity,
        SealedChildOutputAuthority* output,
        const unsigned char* deferred_step3,
        std::size_t deferred_step3_size,
        const unsigned char* open_step2,
        std::size_t open_step2_size)
    : storage_(storage), destroy_(destroy), completion_(completion),
      sealed_output_identity_(sealed_output_identity), output_(output),
      deferred_step3_(deferred_step3),
      deferred_step3_size_(deferred_step3_size), open_step2_(open_step2),
      open_step2_size_(open_step2_size) {
    need(storage_ != nullptr && destroy_ != nullptr &&
         completion_ != nullptr && sealed_output_identity_ != nullptr &&
         output_ != nullptr && deferred_step3_ != nullptr &&
         open_step2_ != nullptr);
}

ObservationOutputFanoutTransfer::ObservationOutputFanoutTransfer(
        ObservationOutputFanoutTransfer&& other) noexcept
    : storage_(std::exchange(other.storage_, nullptr)),
      destroy_(std::exchange(other.destroy_, nullptr)),
      completion_(std::exchange(other.completion_, nullptr)),
      sealed_output_identity_(
          std::exchange(other.sealed_output_identity_, nullptr)),
      output_(std::exchange(other.output_, nullptr)),
      deferred_step3_(std::exchange(other.deferred_step3_, nullptr)),
      deferred_step3_size_(
          std::exchange(other.deferred_step3_size_, 0)),
      open_step2_(std::exchange(other.open_step2_, nullptr)),
      open_step2_size_(std::exchange(other.open_step2_size_, 0)) {}

ObservationOutputFanoutTransfer::~ObservationOutputFanoutTransfer() {
    if (storage_ != nullptr) destroy_(storage_);
}

ObservationOutputJoinAuthority::ObservationOutputJoinAuthority(
        Storage* storage, void (*destroy)(void*) noexcept)
    : storage_(storage), destroy_(destroy) {
    need(storage_ != nullptr && destroy_ != nullptr);
}

ObservationOutputJoinAuthority::ObservationOutputJoinAuthority(
        ObservationOutputJoinAuthority&& other) noexcept
    : storage_(std::exchange(other.storage_, nullptr)),
      destroy_(std::exchange(other.destroy_, nullptr)) {}

ObservationOutputFanoutTransfer
ObservationOutputJoinAuthority::transfer_for_observation_fanout() && {
    void* claimed = std::exchange(storage_, nullptr);
    auto destroy = std::exchange(destroy_, nullptr);
    need(claimed != nullptr && destroy != nullptr);
    try {
        auto& selected = *static_cast<Storage*>(claimed);
        validate_completion(
            selected.binding.completion,
            selected.binding.sealed_output_identity);
        need(runtime_bridge::validate_observer_phase_v2_section(
                 selected.deferred_step3) &&
             runtime_bridge::validate_observer_step2_v3_section(
                 selected.open_step2));
        validate_exact_open_inventory(selected.open_step2);
        return ObservationOutputFanoutTransfer(
            claimed, destroy, &selected.binding.completion,
            &selected.binding.sealed_output_identity, &selected.output,
            selected.deferred_step3.data(), selected.deferred_step3.size(),
            selected.open_step2.data(), selected.open_step2.size());
    } catch (...) {
        destroy(claimed);
        refuse();
    }
}

ObservationOutputJoinAuthority
NativePrivacyPhaseScopeBridge::validate_for_observation(
        SealedChildOutputAuthority&& supplied_output,
        NativeEmpiricalResultAuthority&& supplied_empirical) {
    // Burn both caller capabilities first. Any later failure destroys the
    // retained FD and empirical residual; no independently reusable alias is
    // created.
    SealedChildOutputAuthority output(std::move(supplied_output));
    NativeEmpiricalResultAuthority empirical_input(
        std::move(supplied_empirical));
    PrivatePhaseBinding binding(
        output.retained_completion(), output.retained_identity());
    auto empirical = std::move(empirical_input)
        .transfer_for_observation_output_join(
            binding.completion.offer.binding);
    validate_completion(binding.completion, binding.sealed_output_identity);
    const int fd = output.native_phase_scope_read_fd();
    validate_sealed_fd(fd);
    std::array<unsigned char, OBSERVER_OUTPUT_ABI.magic.size()> magic{};
    std::array<unsigned char, OBSERVER_PHASE_V2_BYTES> phase{};
    std::array<unsigned char, OBSERVER_STEP2_V3_BYTES> step2{};
    read_exact(fd, magic, 0);
    read_exact(fd, phase, static_cast<off_t>(OBSERVER_PHASE_V2_OFFSET));
    read_exact(fd, step2, static_cast<off_t>(OBSERVER_STEP2_V3_OFFSET));
    need(magic == OBSERVER_OUTPUT_ABI.magic &&
         runtime_bridge::validate_observer_phase_v2_section(phase));
    validate_exact_open_inventory(step2);
    auto* storage = new ObservationOutputJoinAuthority::Storage(
            std::move(binding), std::move(output), std::move(empirical),
            std::move(phase), std::move(step2));
    return ObservationOutputJoinAuthority(storage, [](void* value) noexcept {
        delete static_cast<ObservationOutputJoinAuthority::Storage*>(value);
    });
}

} // namespace kpb::measurement::phase_scope
