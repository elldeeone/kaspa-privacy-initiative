#pragma once

// Opaque, linear authority chain for honest owner material and exact public
// output production.  Production callers can move authorities but cannot
// provide or read rho, blinds, ephemeral keys, invoice key indices, NFs, or
// Output520 bytes.  The genuine source-worker minters are deliberately absent
// until that worker is connected; configuration therefore remains false.

#include "honest_owner_material_v3_contract.hpp"
#include "privacy_measurement_authority.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <stdexcept>

namespace kpb::native_terminal {
class MatchedNativeTerminalProducerBundle;
class TerminalV2ModelAdmissionAuthority;
}

namespace kpb::honest_owner_material {

using Digest = measurement::Digest;
using Invoice208 = std::array<unsigned char, 208>;
using Output520 = std::array<unsigned char, 520>;
using Projection10685 = std::array<std::byte, 10685>;

class HonestOwnerRefused final : public std::runtime_error {
public:
    HonestOwnerRefused();
};

class HonestInvoiceSourceAuthority;
class HonestOwnerOutputAuthority;
class HonestOwnerProductionAuthority;
class HonestOwnerTwoRoundProductionAuthority;

#ifdef KPB_HONEST_OWNER_MATERIAL_TEST_SETUP
enum class HonestOwnerTestFault : unsigned char {
    None = 0,
    WrongRound = 1,
    WrongOwner = 2,
    WrongNullifier = 3,
    WrongOutputRow = 4,
    WrongProjection = 5,
    WrongRunBinding = 6,
};

// Test injection is intentionally named, macro-gated, and implemented in a
// separate TU.  Nothing here is a production source or privacy evidence.
class HonestOwnerMaterialTestFixture final {
    HonestOwnerMaterialTestFixture() = delete;
public:
    static HonestInvoiceSourceAuthority invoice_source(
        const measurement::RunBinding&, Digest accepted_history_identity,
        unsigned round, unsigned owner, unsigned output_slot,
        std::uint64_t invoice_index, Invoice208);
    static HonestOwnerOutputAuthority output_source(
        const measurement::RunBinding&, Digest accepted_history_identity,
        unsigned round, unsigned owner, unsigned output_slot,
        std::uint64_t invoice_index, Invoice208, Digest public_nullifier,
        Output520);
    static HonestOwnerTwoRoundProductionAuthority two_rounds(
        const measurement::RunBinding&,
        const std::array<Projection10685, 2>&,
        HonestOwnerTestFault = HonestOwnerTestFault::None);
};
#endif

class HonestInvoiceSourceAuthority final {
    measurement::RunBinding binding_;
    Digest binding_identity_{};
    Digest accepted_history_identity_{};
    Digest generation_identity_{};
    unsigned round_{};
    unsigned owner_{};
    unsigned output_slot_{};
    std::uint64_t invoice_index_{};
    Invoice208 invoice_{};
    std::atomic_bool live_{true};

    HonestInvoiceSourceAuthority(
        measurement::RunBinding, Digest, unsigned, unsigned, unsigned,
        std::uint64_t, Invoice208, Digest);
    friend class V3InvoiceMaterialMinter;
#ifdef KPB_HONEST_OWNER_MATERIAL_TEST_SETUP
    friend class HonestOwnerMaterialTestFixture;
#endif
public:
    HonestInvoiceSourceAuthority(const HonestInvoiceSourceAuthority&) = delete;
    HonestInvoiceSourceAuthority& operator=(
        const HonestInvoiceSourceAuthority&) = delete;
    HonestInvoiceSourceAuthority(HonestInvoiceSourceAuthority&&) noexcept;
    HonestInvoiceSourceAuthority& operator=(
        HonestInvoiceSourceAuthority&&) = delete;
};

class HonestOwnerOutputAuthority final {
    measurement::RunBinding binding_;
    Digest binding_identity_{};
    Digest accepted_history_identity_{};
    Digest generation_identity_{};
    Digest source_worker_identity_{};
    Digest output_verifier_identity_{};
    Digest crypto_bridge_identity_{};
    Digest statement_identity_{};
    unsigned round_{};
    unsigned owner_{};
    unsigned output_slot_{};
    std::uint64_t invoice_index_{};
    Invoice208 invoice_{};
    Digest public_nullifier_{};
    Output520 output_{};
    bool source_owned_rho_{};
    bool source_owned_blinds_{};
    bool source_owned_ephemeral_key_{};
    bool source_owned_invoice_index_{};
    bool output_proof_verified_{};
    bool exact_statement_correspondence_{};
    std::atomic_bool live_{true};

    void validate_source() const;
    HonestOwnerOutputAuthority(
        measurement::RunBinding, Digest, unsigned, unsigned, unsigned,
        std::uint64_t, Invoice208, Digest, Output520, Digest, Digest, Digest,
        Digest, Digest);
    friend class V3InvoiceMaterialMinter;
    friend class HonestOwnerProductionAuthority;
#ifdef KPB_HONEST_OWNER_MATERIAL_TEST_SETUP
    friend class HonestOwnerMaterialTestFixture;
#endif
public:
    HonestOwnerOutputAuthority(const HonestOwnerOutputAuthority&) = delete;
    HonestOwnerOutputAuthority& operator=(
        const HonestOwnerOutputAuthority&) = delete;
    HonestOwnerOutputAuthority(HonestOwnerOutputAuthority&&) noexcept;
    HonestOwnerOutputAuthority& operator=(HonestOwnerOutputAuthority&&) =
        delete;
};

class HonestOwnerProductionAuthority final {
    measurement::RunBinding binding_;
    Digest binding_identity_{};
    Digest accepted_history_identity_{};
    Digest generation_identity_{};
    Digest source_worker_identity_{};
    Digest output_verifier_identity_{};
    Digest crypto_bridge_identity_{};
    Digest statement_identity_{};
    unsigned round_{};
    unsigned owner_{};
    unsigned output_slot_{};
    std::uint64_t invoice_index_{};
    Invoice208 invoice_{};
    Digest public_nullifier_{};
    Output520 output_{};
    std::atomic_bool live_{true};

    void validate_consumed() const;
    HonestOwnerProductionAuthority(HonestOwnerOutputAuthority&&);
    friend class V3InvoiceMaterialMinter;
    friend class HonestOwnerProductionJoin;
public:
    HonestOwnerProductionAuthority(
        const HonestOwnerProductionAuthority&) = delete;
    HonestOwnerProductionAuthority& operator=(
        const HonestOwnerProductionAuthority&) = delete;
    HonestOwnerProductionAuthority(
        HonestOwnerProductionAuthority&&) noexcept;
    HonestOwnerProductionAuthority& operator=(
        HonestOwnerProductionAuthority&&) = delete;
};

class HonestOwnerProductionJoin final {
    HonestOwnerProductionJoin() = delete;
public:
    // Required order is R1/O0/S0, R1/O0/S1, ... R2/O2/S1.  Identity comes
    // only from the consumed source authorities; no caller binding is accepted.
    static HonestOwnerTwoRoundProductionAuthority complete(
        std::array<HonestOwnerProductionAuthority, 12>&&);
};

class HonestOwnerTwoRoundProductionAuthority final {
    struct SlotProduction {
        Digest accepted_history_identity{};
        Digest generation_identity{};
        Digest source_worker_identity{};
        Digest output_verifier_identity{};
        Digest crypto_bridge_identity{};
        Digest statement_identity{};
        unsigned round{};
        unsigned owner{};
        unsigned output_slot{};
        std::uint64_t invoice_index{};
        Invoice208 invoice{};
        Digest public_nullifier{};
        Output520 output{};
        bool operator==(const SlotProduction&) const = default;
    };
    struct RoundProduction {
        Digest projection_identity{};
        std::array<Digest, 3> owner_nullifiers{};
        std::array<Output520, 6> owner_slot_outputs{};
        bool operator==(const RoundProduction&) const = default;
    };

    measurement::RunBinding binding_;
    Digest binding_identity_{};
    std::array<SlotProduction, 12> slots_{};
    std::array<RoundProduction, 2> rounds_{};
    std::atomic_bool live_{true};

    HonestOwnerTwoRoundProductionAuthority(
        measurement::RunBinding, Digest,
        std::array<SlotProduction, 12>,
        std::array<RoundProduction, 2>);
    void validate_retained() const;
    void validate_for_terminal(
        const measurement::RunBinding&,
        measurement::Classification,
        const std::array<std::array<Digest, 3>, 2>&,
        const std::array<std::array<Output520, 6>, 2>&) const;
    friend class HonestOwnerProductionJoin;
    friend class native_terminal::MatchedNativeTerminalProducerBundle;
    friend class native_terminal::TerminalV2ModelAdmissionAuthority;
#ifdef KPB_HONEST_OWNER_MATERIAL_TEST_SETUP
    friend class HonestOwnerMaterialTestFixture;
#endif
public:
    HonestOwnerTwoRoundProductionAuthority(
        const HonestOwnerTwoRoundProductionAuthority&) = delete;
    HonestOwnerTwoRoundProductionAuthority& operator=(
        const HonestOwnerTwoRoundProductionAuthority&) = delete;
    HonestOwnerTwoRoundProductionAuthority(
        HonestOwnerTwoRoundProductionAuthority&&) noexcept;
    HonestOwnerTwoRoundProductionAuthority& operator=(
        HonestOwnerTwoRoundProductionAuthority&&) = delete;
};

struct HonestOwnerMaterialSourceStatus {
    bool exact_run_binding_before_generation;
    bool round_owner_slot_index_before_generation;
    bool v3_accepted_history_join;
    bool live_parent_exactly_matches_accepted_authority;
    bool accepted_invoice_exact_match;
    bool cm_cv_ciphertext_proof_exact_row_match;
    bool public_nullifier_exact_match;
    bool move_only_terminal_residual;
    bool terminal_v2_factory_requires_residual;
    bool no_public_secret_or_row_getter;
    bool production_invoice_source_minter_available;
    bool production_output_source_minter_available;
    bool selected_owner_worker_integrated;
    bool selected_lifecycle_callsite_integrated;
    bool configured;
};

inline constexpr HonestOwnerMaterialSourceStatus
kHonestOwnerMaterialSourceStatus{
    .exact_run_binding_before_generation = true,
    .round_owner_slot_index_before_generation = true,
    .v3_accepted_history_join = true,
    .live_parent_exactly_matches_accepted_authority = true,
    .accepted_invoice_exact_match = true,
    .cm_cv_ciphertext_proof_exact_row_match = true,
    .public_nullifier_exact_match = true,
    .move_only_terminal_residual = true,
    .terminal_v2_factory_requires_residual = true,
    .no_public_secret_or_row_getter = true,
    .production_invoice_source_minter_available = false,
    .production_output_source_minter_available = false,
    .selected_owner_worker_integrated = false,
    .selected_lifecycle_callsite_integrated = false,
    .configured = false,
};

} // namespace kpb::honest_owner_material
