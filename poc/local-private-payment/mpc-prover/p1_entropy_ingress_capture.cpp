#include "p1_entropy_ingress_capture.hpp"

#include "Tools/random.h"
#include <cryptoTools/Common/Defines.h>

#include <array>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <limits>
#include <mutex>
#include <span>
#include <stdexcept>
#include <utility>

namespace kpi::mpc::p1_private_state {
namespace {

struct ActiveCapture final {
    EntropyStateHook* hook{};
    std::uint64_t generation{};
    std::uint64_t next_object_epoch{1};
    std::uint64_t next_allocation_epoch{1};
    // Epoch one is reserved at installation for the genuine role-child
    // thread. A worker that wins the first entropy callback must never be
    // mistaken for the recorder root thread.
    std::uint64_t next_thread_epoch{2};
    std::array<std::uint64_t, 3> counters{};
    bool healthy{true};
};

std::mutex capture_mutex;
ActiveCapture* active_capture{};
std::atomic<std::uint64_t> next_generation{1};

struct ThreadEpoch final {
    std::uint64_t generation{};
    std::uint64_t epoch{};
};
thread_local ThreadEpoch thread_epoch;

void mark_unavailable_locked(
        ActiveCapture& active, EntropySource source) noexcept {
    if (!active.healthy) return;
    active.healthy = false;
    active.hook->entropy_unavailable_noexcept(source);
}

enum class RetainResult { NoCapture, Retained, Failed };

std::uint64_t selected_callsite_rva(
        void* caller, const void* wrapper) noexcept {
    Dl_info caller_info{};
    Dl_info wrapper_info{};
    if (!caller || !wrapper ||
        ::dladdr(caller, &caller_info) == 0 ||
        ::dladdr(wrapper, &wrapper_info) == 0 ||
        caller_info.dli_fbase == nullptr || wrapper_info.dli_fbase == nullptr ||
        caller_info.dli_fbase != wrapper_info.dli_fbase)
        return 0;
    const auto address = reinterpret_cast<std::uintptr_t>(caller);
    const auto base = reinterpret_cast<std::uintptr_t>(caller_info.dli_fbase);
    if (address <= base) return 0;
    return static_cast<std::uint64_t>(address - base);
}

RetainResult retain_entropy(
        EntropySource source,
        std::span<const unsigned char> exact_entropy,
        void* caller, const void* wrapper) noexcept {
    std::lock_guard lock(capture_mutex);
    auto* active = active_capture;
    if (!active) return RetainResult::NoCapture;
    if (!active->healthy) return RetainResult::Failed;
    const auto callsite_rva = selected_callsite_rva(caller, wrapper);
    const auto ordinal = static_cast<unsigned>(source);
    const auto index = ordinal == 0 ? 3 : ordinal - 1;
    if (callsite_rva == 0 || index >= active->counters.size() ||
        active->next_object_epoch ==
            std::numeric_limits<std::uint64_t>::max() ||
        active->next_allocation_epoch ==
            std::numeric_limits<std::uint64_t>::max() ||
        active->next_thread_epoch ==
            std::numeric_limits<std::uint64_t>::max() ||
        active->counters[index] ==
            std::numeric_limits<std::uint64_t>::max()) {
        mark_unavailable_locked(*active, source);
        return RetainResult::Failed;
    }
    if (thread_epoch.generation != active->generation) {
        thread_epoch.generation = active->generation;
        thread_epoch.epoch = active->next_thread_epoch++;
    }
    const auto before = active->counters[index]++;
    const EntropyIngressView view{
        .source = source,
        .callsite_rva = callsite_rva,
        .object_epoch = active->next_object_epoch++,
        .thread_epoch = thread_epoch.epoch,
        .allocation_epoch = active->next_allocation_epoch++,
        .counter_before = before,
        .counter_after = before + 1,
        .exact_entropy = exact_entropy,
    };
    if (!active->hook->record_entropy_ingress(view)) {
        mark_unavailable_locked(*active, source);
        return RetainResult::Failed;
    }
    return RetainResult::Retained;
}

void source_failed(EntropySource source) noexcept {
    std::lock_guard lock(capture_mutex);
    if (active_capture) mark_unavailable_locked(*active_capture, source);
}

void require_retained(
        EntropySource source,
        std::span<const unsigned char> exact_entropy,
        void* caller, const void* wrapper) noexcept {
    if (retain_entropy(source, exact_entropy, caller, wrapper) ==
        RetainResult::Failed)
        std::abort();
}

} // namespace

struct EntropyIngressCapture::Storage final {
    std::unique_ptr<EntropyStateHook> hook;
    ActiveCapture active;
    bool installed{};
};

EntropyIngressCapture::EntropyIngressCapture(std::unique_ptr<Storage> storage)
    : storage_(std::move(storage)) {}

EntropyIngressCapture EntropyIngressCapture::begin_impl(
        std::unique_ptr<EntropyStateHook>&& hook) {
    if (!hook) throw std::runtime_error("P1-entropy-adapter-absent");
    auto storage = std::make_unique<Storage>();
    storage->hook = std::move(hook);
    storage->active.hook = storage->hook.get();
    const auto generation = next_generation.fetch_add(1);
    if (generation == 0 ||
        generation == std::numeric_limits<std::uint64_t>::max())
        throw std::runtime_error("P1-entropy-generation-exhausted");
    storage->active.generation = generation;
    thread_epoch = ThreadEpoch{
        .generation = generation,
        .epoch = 1,
    };
    {
        std::lock_guard lock(capture_mutex);
        if (active_capture != nullptr)
            throw std::runtime_error("P1-entropy-capture-already-installed");
        active_capture = &storage->active;
        storage->installed = true;
    }
    return EntropyIngressCapture(std::move(storage));
}

EntropyIngressCapture EntropyIngressCapture::begin(
        std::unique_ptr<
            ::kpb::measurement::p1_state_capsule::P1EntropyStateAdapter>&&
            adapter) {
    if (!adapter)
        throw std::runtime_error("P1-entropy-adapter-absent");
    std::unique_ptr<EntropyStateHook> hook(std::move(adapter));
    return begin_impl(std::move(hook));
}

#ifdef KPI_P1_ENTROPY_STATE_HOOK_TEST_SETUP
EntropyIngressCapture EntropyIngressCapture::test_only_begin(
        std::unique_ptr<EntropyStateHook>&& hook) {
    return begin_impl(std::move(hook));
}
#endif

EntropyIngressCapture::EntropyIngressCapture(
        EntropyIngressCapture&& other) noexcept = default;

EntropyIngressCapture::~EntropyIngressCapture() {
    if (!storage_ || !storage_->installed) return;
    std::lock_guard lock(capture_mutex);
    if (active_capture == &storage_->active) {
        storage_->active.hook->entropy_unavailable_noexcept(
            EntropySource::MpSpdzPrngReseed);
        storage_->active.healthy = false;
        active_capture = nullptr;
    }
    storage_->installed = false;
}

bool EntropyIngressCapture::finish_noexcept() && noexcept {
    if (!storage_ || !storage_->installed) return false;
    std::lock_guard lock(capture_mutex);
    if (active_capture != &storage_->active) return false;
    const bool healthy = storage_->active.healthy &&
        storage_->active.hook->entropy_capture_terminal_noexcept();
    active_capture = nullptr;
    storage_->installed = false;
    return healthy;
}

} // namespace kpi::mpc::p1_private_state

// Preserve the exact pinned implementations. GNU ld rewrites only selected
// unresolved ingress calls to __wrap_*; __real_* resolves to the original
// pinned shared/static object. Failure to retain an active P1 event is fail-stop.
extern "C" void __real__ZN4PRNG6ReSeedEv(PRNG*);
extern "C" void __wrap__ZN4PRNG6ReSeedEv(PRNG* value) {
    void* const caller =
        __builtin_extract_return_addr(__builtin_return_address(0));
    try {
        __real__ZN4PRNG6ReSeedEv(value);
    } catch (...) {
        kpi::mpc::p1_private_state::source_failed(
            kpi::mpc::p1_private_state::EntropySource::MpSpdzPrngReseed);
        throw;
    }
    kpi::mpc::p1_private_state::require_retained(
        kpi::mpc::p1_private_state::EntropySource::MpSpdzPrngReseed,
        std::span(value->get_seed(), static_cast<std::size_t>(SEED_SIZE)),
        caller, reinterpret_cast<const void*>(&__wrap__ZN4PRNG6ReSeedEv));
}

extern "C" void __real_simplestot_randombytes(
    unsigned char*, unsigned long long);
extern "C" void __wrap_simplestot_randombytes(
        unsigned char* output, unsigned long long size) {
    void* const caller =
        __builtin_extract_return_addr(__builtin_return_address(0));
    __real_simplestot_randombytes(output, size);
    if (size > std::numeric_limits<std::size_t>::max()) {
        kpi::mpc::p1_private_state::source_failed(
            kpi::mpc::p1_private_state::EntropySource::
                SimplestOtRandomBytes);
        std::abort();
    }
    kpi::mpc::p1_private_state::require_retained(
        kpi::mpc::p1_private_state::EntropySource::SimplestOtRandomBytes,
        std::span(output, static_cast<std::size_t>(size)), caller,
        reinterpret_cast<const void*>(&__wrap_simplestot_randombytes));
}

extern "C" osuCrypto::block __real__ZN9osuCrypto13sysRandomSeedEv();
extern "C" osuCrypto::block __wrap__ZN9osuCrypto13sysRandomSeedEv() {
    void* const caller =
        __builtin_extract_return_addr(__builtin_return_address(0));
    osuCrypto::block value;
    try {
        value = __real__ZN9osuCrypto13sysRandomSeedEv();
    } catch (...) {
        kpi::mpc::p1_private_state::source_failed(
            kpi::mpc::p1_private_state::EntropySource::
                CryptoToolsSystemSeed);
        throw;
    }
    std::array<unsigned char, sizeof(value)> bytes{};
    std::memcpy(bytes.data(), &value, bytes.size());
    kpi::mpc::p1_private_state::require_retained(
        kpi::mpc::p1_private_state::EntropySource::CryptoToolsSystemSeed,
        bytes, caller,
        reinterpret_cast<const void*>(
            &__wrap__ZN9osuCrypto13sysRandomSeedEv));
    return value;
}
