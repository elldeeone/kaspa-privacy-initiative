#include "honest_owner_material_authority.hpp"

#include "../../future-recipient/v3/v3_native_authority.hpp"

#include <algorithm>
#include <cstring>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace kpb::honest_owner_material {
namespace {

using Bytes = std::vector<unsigned char>;
namespace v3_native = future_recipient::v3_native;

[[noreturn]] void refuse() { throw HonestOwnerRefused(); }
void need(bool value) { if (!value) refuse(); }

bool nonzero(const Digest& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

template<std::size_t Size>
bool nonzero(const std::array<unsigned char, Size>& value) {
    return std::any_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte != 0; });
}

template<std::size_t Size>
bool exact(const std::array<unsigned char, Size>& left,
           const std::array<unsigned char, Size>& right) {
    return CRYPTO_memcmp(left.data(), right.data(), Size) == 0;
}

void add(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}
template<std::size_t Size>
void add(Bytes& out, const std::array<unsigned char, Size>& value) {
    add(out, std::span(value));
}
void add(Bytes& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}
void little(Bytes& out, std::uint64_t value, unsigned width = 8) {
    need(width > 0 && width <= 8);
    for (unsigned index = 0; index < width; ++index)
        out.push_back(static_cast<unsigned char>(value >> (8 * index)));
}

Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    need(SHA256(value.data(), value.size(), result.data()) != nullptr);
    return result;
}

std::uint64_t invoice_index(const Invoice208& invoice) {
    need(std::memcmp(invoice.data(), "KPX3IN01", 8) == 0);
    std::uint64_t result = 0;
    for (unsigned index = 0; index < 8; ++index)
        result |= static_cast<std::uint64_t>(invoice[40 + index]) <<
            (8 * index);
    return result;
}

void validate_invoice(const Invoice208& invoice, std::uint64_t index) {
    need(invoice_index(invoice) == index);
    for (const auto offset : {8U, 48U, 80U, 112U, 144U, 176U})
        need(std::any_of(invoice.begin() + offset,
                         invoice.begin() + offset + 32,
                         [](unsigned char byte) { return byte != 0; }));
}

Digest generation_identity(
        const Digest& binding_identity,
        const Digest& accepted_history_identity,
        unsigned round, unsigned owner, unsigned output_slot,
        std::uint64_t index, const Invoice208& invoice) {
    Bytes bytes;
    add(bytes, "KPB_HONEST_OWNER_PREGENERATION_V1\n");
    add(bytes, binding_identity);
    add(bytes, accepted_history_identity);
    little(bytes, round, 4);
    little(bytes, owner, 4);
    little(bytes, output_slot, 4);
    little(bytes, index);
    add(bytes, invoice);
    return hash(bytes);
}

Digest statement_identity(
        const Digest& binding_identity,
        const Digest& accepted_history_identity,
        const Digest& generation,
        const Digest& source_worker,
        const Digest& output_verifier,
        const Digest& crypto_bridge,
        unsigned round, unsigned owner, unsigned output_slot,
        std::uint64_t index, const Invoice208& invoice,
        const Digest& public_nullifier, const Output520& output) {
    Bytes bytes;
    add(bytes, "KPB_HONEST_OWNER_OUTPUT_STATEMENT_V1\n");
    for (const auto* field : {
             &binding_identity, &accepted_history_identity, &generation,
             &source_worker, &output_verifier, &crypto_bridge,
             &public_nullifier})
        add(bytes, *field);
    little(bytes, round, 4);
    little(bytes, owner, 4);
    little(bytes, output_slot, 4);
    little(bytes, index);
    add(bytes, invoice);
    add(bytes, output);
    return hash(bytes);
}

Digest binding_identity(const measurement::RunBinding& binding) {
    try {
        measurement::validate_measurement_run_binding(binding);
        return v3_native::recompute_v3_run_binding_identity(binding);
    } catch (...) {
        refuse();
    }
}

void validate_common(
        const measurement::RunBinding& binding,
        const Digest& selected_binding_identity,
        const Digest& accepted_history_identity,
        const Digest& generation, unsigned round, unsigned owner,
        unsigned output_slot, std::uint64_t index,
        const Invoice208& invoice) {
    const auto expected_binding = binding_identity(binding);
    need(exact(selected_binding_identity, expected_binding) &&
         nonzero(accepted_history_identity) &&
         !exact(accepted_history_identity, selected_binding_identity) &&
         (round == 1 || round == 2) && owner < 3 && output_slot < 2);
    validate_invoice(invoice, index);
    need(exact(generation, generation_identity(
         selected_binding_identity, accepted_history_identity,
         round, owner, output_slot, index, invoice)));
}

void validate_output_row(const Output520& output) {
    const auto first_nonzero = [](const unsigned char* begin,
                                  const unsigned char* end) {
        return std::any_of(begin, end,
                           [](unsigned char byte) { return byte != 0; });
    };
    need(first_nonzero(output.data(), output.data() + 32) &&
         first_nonzero(output.data() + 32, output.data() + 96) &&
         first_nonzero(output.data() + 96, output.data() + 128) &&
         first_nonzero(output.data() + 392, output.data() + 520));
    const auto ciphertext_hash = hash(
        {output.data() + 96, 264});
    need(CRYPTO_memcmp(ciphertext_hash.data(), output.data() + 360,
                       ciphertext_hash.size()) == 0);
}

template<class Value, std::size_t Count>
bool same_multiset(std::array<Value, Count> left,
                   std::array<Value, Count> right) {
    std::sort(left.begin(), left.end());
    std::sort(right.begin(), right.end());
    return left == right;
}

} // namespace

HonestOwnerRefused::HonestOwnerRefused()
    : std::runtime_error("honest owner material refused") {}

HonestInvoiceSourceAuthority::HonestInvoiceSourceAuthority(
        measurement::RunBinding binding, Digest accepted_history,
        unsigned round, unsigned owner, unsigned output_slot,
        std::uint64_t index, Invoice208 invoice, Digest generation)
    : binding_(std::move(binding)),
      binding_identity_(binding_identity(binding_)),
      accepted_history_identity_(accepted_history),
      generation_identity_(generation), round_(round), owner_(owner),
      output_slot_(output_slot), invoice_index_(index), invoice_(invoice) {
    validate_common(
        binding_, binding_identity_, accepted_history_identity_,
        generation_identity_, round_, owner_, output_slot_, invoice_index_,
        invoice_);
}

HonestInvoiceSourceAuthority::HonestInvoiceSourceAuthority(
        HonestInvoiceSourceAuthority&& other) noexcept
    : binding_(std::move(other.binding_)),
      binding_identity_(other.binding_identity_),
      accepted_history_identity_(other.accepted_history_identity_),
      generation_identity_(other.generation_identity_),
      round_(other.round_), owner_(other.owner_),
      output_slot_(other.output_slot_), invoice_index_(other.invoice_index_),
      invoice_(other.invoice_), live_(other.live_.exchange(false)) {}

HonestOwnerOutputAuthority::HonestOwnerOutputAuthority(
        measurement::RunBinding binding, Digest accepted_history,
        unsigned round, unsigned owner, unsigned output_slot,
        std::uint64_t index, Invoice208 invoice, Digest public_nullifier,
        Output520 output, Digest generation, Digest source_worker,
        Digest output_verifier, Digest crypto_bridge, Digest statement)
    : binding_(std::move(binding)),
      binding_identity_(binding_identity(binding_)),
      accepted_history_identity_(accepted_history),
      generation_identity_(generation),
      source_worker_identity_(source_worker),
      output_verifier_identity_(output_verifier),
      crypto_bridge_identity_(crypto_bridge),
      statement_identity_(statement), round_(round), owner_(owner),
      output_slot_(output_slot), invoice_index_(index), invoice_(invoice),
      public_nullifier_(public_nullifier), output_(output),
      source_owned_rho_(true), source_owned_blinds_(true),
      source_owned_ephemeral_key_(true),
      source_owned_invoice_index_(true), output_proof_verified_(true),
      exact_statement_correspondence_(true) {
    validate_source();
}

void HonestOwnerOutputAuthority::validate_source() const {
    validate_common(
        binding_, binding_identity_, accepted_history_identity_,
        generation_identity_, round_, owner_, output_slot_, invoice_index_,
        invoice_);
    need(nonzero(public_nullifier_) && nonzero(source_worker_identity_) &&
         nonzero(output_verifier_identity_) &&
         nonzero(crypto_bridge_identity_) && source_owned_rho_ &&
         source_owned_blinds_ && source_owned_ephemeral_key_ &&
         source_owned_invoice_index_ && output_proof_verified_ &&
         exact_statement_correspondence_);
    validate_output_row(output_);
    need(exact(statement_identity_, statement_identity(
         binding_identity_, accepted_history_identity_, generation_identity_,
         source_worker_identity_, output_verifier_identity_,
         crypto_bridge_identity_, round_, owner_, output_slot_,
         invoice_index_, invoice_, public_nullifier_, output_)));
}

HonestOwnerOutputAuthority::HonestOwnerOutputAuthority(
        HonestOwnerOutputAuthority&& other) noexcept
    : binding_(std::move(other.binding_)),
      binding_identity_(other.binding_identity_),
      accepted_history_identity_(other.accepted_history_identity_),
      generation_identity_(other.generation_identity_),
      source_worker_identity_(other.source_worker_identity_),
      output_verifier_identity_(other.output_verifier_identity_),
      crypto_bridge_identity_(other.crypto_bridge_identity_),
      statement_identity_(other.statement_identity_), round_(other.round_),
      owner_(other.owner_), output_slot_(other.output_slot_),
      invoice_index_(other.invoice_index_), invoice_(other.invoice_),
      public_nullifier_(other.public_nullifier_), output_(other.output_),
      source_owned_rho_(other.source_owned_rho_),
      source_owned_blinds_(other.source_owned_blinds_),
      source_owned_ephemeral_key_(other.source_owned_ephemeral_key_),
      source_owned_invoice_index_(other.source_owned_invoice_index_),
      output_proof_verified_(other.output_proof_verified_),
      exact_statement_correspondence_(
          other.exact_statement_correspondence_),
      live_(other.live_.exchange(false)) {}

#ifdef KPB_HONEST_OWNER_MATERIAL_TEST_SETUP
HonestInvoiceSourceAuthority V3InvoiceMaterialMinter::test_only_bind_to_parent(
        HonestInvoiceSourceAuthority&& source,
        v3_native::ParentV3Authority& parent) {
    HonestInvoiceSourceAuthority claimed(std::move(source));
    need(claimed.live_.exchange(false) &&
         exact(claimed.binding_identity_, parent.binding_identity_) &&
         nonzero(parent.accepted_history_identity_) &&
         nonzero(parent.instance_identity_));
    const auto regenerated = generation_identity(
        claimed.binding_identity_, parent.accepted_history_identity_,
        claimed.round_, claimed.owner_, claimed.output_slot_,
        claimed.invoice_index_, claimed.invoice_);
    return HonestInvoiceSourceAuthority(
        claimed.binding_, parent.accepted_history_identity_, claimed.round_,
        claimed.owner_, claimed.output_slot_, claimed.invoice_index_,
        claimed.invoice_, regenerated);
}

HonestOwnerOutputAuthority V3InvoiceMaterialMinter::test_only_bind_to_parent(
        HonestOwnerOutputAuthority&& source,
        v3_native::ParentV3Authority& parent) {
    HonestOwnerOutputAuthority claimed(std::move(source));
    need(claimed.live_.exchange(false) &&
         exact(claimed.binding_identity_, parent.binding_identity_) &&
         nonzero(parent.accepted_history_identity_) &&
         nonzero(parent.instance_identity_));
    const auto regenerated = generation_identity(
        claimed.binding_identity_, parent.accepted_history_identity_,
        claimed.round_, claimed.owner_, claimed.output_slot_,
        claimed.invoice_index_, claimed.invoice_);
    const auto restated = statement_identity(
        claimed.binding_identity_, parent.accepted_history_identity_,
        regenerated, claimed.source_worker_identity_,
        claimed.output_verifier_identity_, claimed.crypto_bridge_identity_,
        claimed.round_, claimed.owner_, claimed.output_slot_,
        claimed.invoice_index_, claimed.invoice_,
        claimed.public_nullifier_, claimed.output_);
    return HonestOwnerOutputAuthority(
        claimed.binding_, parent.accepted_history_identity_, claimed.round_,
        claimed.owner_, claimed.output_slot_, claimed.invoice_index_,
        claimed.invoice_, claimed.public_nullifier_, claimed.output_,
        regenerated, claimed.source_worker_identity_,
        claimed.output_verifier_identity_, claimed.crypto_bridge_identity_,
        restated);
}
#endif

HonestOwnerProductionAuthority::HonestOwnerProductionAuthority(
        HonestOwnerOutputAuthority&& value)
    : binding_(std::move(value.binding_)),
      binding_identity_(value.binding_identity_),
      accepted_history_identity_(value.accepted_history_identity_),
      generation_identity_(value.generation_identity_),
      source_worker_identity_(value.source_worker_identity_),
      output_verifier_identity_(value.output_verifier_identity_),
      crypto_bridge_identity_(value.crypto_bridge_identity_),
      statement_identity_(value.statement_identity_), round_(value.round_),
      owner_(value.owner_), output_slot_(value.output_slot_),
      invoice_index_(value.invoice_index_), invoice_(value.invoice_),
      public_nullifier_(value.public_nullifier_), output_(value.output_) {}

HonestOwnerProductionAuthority::HonestOwnerProductionAuthority(
        HonestOwnerProductionAuthority&& other) noexcept
    : binding_(std::move(other.binding_)),
      binding_identity_(other.binding_identity_),
      accepted_history_identity_(other.accepted_history_identity_),
      generation_identity_(other.generation_identity_),
      source_worker_identity_(other.source_worker_identity_),
      output_verifier_identity_(other.output_verifier_identity_),
      crypto_bridge_identity_(other.crypto_bridge_identity_),
      statement_identity_(other.statement_identity_), round_(other.round_),
      owner_(other.owner_), output_slot_(other.output_slot_),
      invoice_index_(other.invoice_index_), invoice_(other.invoice_),
      public_nullifier_(other.public_nullifier_), output_(other.output_),
      live_(other.live_.exchange(false)) {}

void HonestOwnerProductionAuthority::validate_consumed() const {
    validate_common(
        binding_, binding_identity_, accepted_history_identity_,
        generation_identity_, round_, owner_, output_slot_, invoice_index_,
        invoice_);
    need(nonzero(public_nullifier_) && nonzero(source_worker_identity_) &&
         nonzero(output_verifier_identity_) &&
         nonzero(crypto_bridge_identity_));
    validate_output_row(output_);
    need(exact(statement_identity_, statement_identity(
         binding_identity_, accepted_history_identity_, generation_identity_,
         source_worker_identity_, output_verifier_identity_,
         crypto_bridge_identity_, round_, owner_, output_slot_,
         invoice_index_, invoice_, public_nullifier_, output_)));
}

v3_native::InvoiceMaterialAuthority V3InvoiceMaterialMinter::mint(
        HonestInvoiceSourceAuthority&& source,
        v3_native::ParentV3Authority& parent,
        const measurement::RunBinding& binding) {
    HonestInvoiceSourceAuthority claimed(std::move(source));
    need(claimed.live_.exchange(false));
    validate_common(
        claimed.binding_, claimed.binding_identity_,
        claimed.accepted_history_identity_, claimed.generation_identity_,
        claimed.round_, claimed.owner_, claimed.output_slot_,
        claimed.invoice_index_, claimed.invoice_);
    const auto expected_binding = binding_identity(binding);
    need(claimed.binding_ == binding &&
         exact(claimed.binding_identity_, expected_binding) &&
         exact(parent.binding_identity_, expected_binding) &&
         nonzero(parent.accepted_history_identity_) &&
         exact(claimed.accepted_history_identity_,
               parent.accepted_history_identity_));
    return v3_native::InvoiceMaterialAuthority(
        claimed.invoice_, parent.binding_identity_,
        parent.accepted_history_identity_, parent.instance_identity_,
        claimed.generation_identity_);
}

HonestOwnerProductionAuthority V3InvoiceMaterialMinter::consume_for_output(
        v3_native::ParentV3Authority& parent,
        v3_native::AcceptedInvoiceAuthority&& accepted,
        HonestOwnerOutputAuthority&& output) {
    v3_native::AcceptedInvoiceAuthority claimed_accepted(
        std::move(accepted));
    HonestOwnerOutputAuthority claimed_output(std::move(output));
    try {
        need(claimed_accepted.live_.load() &&
             claimed_output.live_.exchange(false) &&
             claimed_accepted.parent_ == &parent &&
             exact(claimed_accepted.parent_instance_identity_,
                   parent.instance_identity_));
        claimed_output.validate_source();
        need(exact(claimed_output.binding_identity_,
                   parent.binding_identity_) &&
             nonzero(parent.accepted_history_identity_) &&
             exact(claimed_output.accepted_history_identity_,
                   parent.accepted_history_identity_) &&
             exact(claimed_accepted.source_generation_identity_,
                   claimed_output.generation_identity_) &&
             claimed_accepted.index_ == claimed_output.invoice_index_ &&
             exact(claimed_accepted.invoice_, claimed_output.invoice_));
        parent.consume(std::move(claimed_accepted));
        return HonestOwnerProductionAuthority(std::move(claimed_output));
    } catch (...) {
        if (claimed_accepted.parent_ == &parent &&
            exact(claimed_accepted.parent_instance_identity_,
                  parent.instance_identity_) &&
            claimed_accepted.live_.load()) {
            try { parent.poison(std::move(claimed_accepted)); }
            catch (...) {}
        }
        refuse();
    }
}

HonestOwnerTwoRoundProductionAuthority HonestOwnerProductionJoin::complete(
        std::array<HonestOwnerProductionAuthority, 12>&& authorities) {
    bool all_live = true;
    for (auto& value : authorities)
        all_live = value.live_.exchange(false) && all_live;
    need(all_live);

    const auto binding = authorities[0].binding_;
    const auto selected_binding_identity = authorities[0].binding_identity_;
    std::array<HonestOwnerTwoRoundProductionAuthority::SlotProduction, 12>
        slots{};
    std::array<HonestOwnerTwoRoundProductionAuthority::RoundProduction, 2>
        rounds{};
    for (unsigned index = 0; index < authorities.size(); ++index) {
        const auto& value = authorities[index];
        value.validate_consumed();
        const unsigned expected_round = index / 6 + 1;
        const unsigned expected_owner = (index % 6) / 2;
        const unsigned expected_slot = index % 2;
        need(value.binding_ == binding &&
             exact(value.binding_identity_, selected_binding_identity) &&
             value.round_ == expected_round &&
             value.owner_ == expected_owner &&
             value.output_slot_ == expected_slot);
        if (index > 0)
            need(exact(value.accepted_history_identity_,
                       authorities[0].accepted_history_identity_));
        slots[index] = {
            .accepted_history_identity = value.accepted_history_identity_,
            .generation_identity = value.generation_identity_,
            .source_worker_identity = value.source_worker_identity_,
            .output_verifier_identity = value.output_verifier_identity_,
            .crypto_bridge_identity = value.crypto_bridge_identity_,
            .statement_identity = value.statement_identity_,
            .round = value.round_, .owner = value.owner_,
            .output_slot = value.output_slot_,
            .invoice_index = value.invoice_index_, .invoice = value.invoice_,
            .public_nullifier = value.public_nullifier_,
            .output = value.output_,
        };
        auto& round = rounds[expected_round - 1];
        round.projection_identity = binding.projections[expected_round - 1];
        round.owner_nullifiers[expected_owner] = value.public_nullifier_;
        round.owner_slot_outputs[expected_owner * 2 + expected_slot] =
            value.output_;
        if (expected_slot == 1)
            need(exact(value.public_nullifier_,
                       authorities[index - 1].public_nullifier_));
    }
    return HonestOwnerTwoRoundProductionAuthority(
        binding, selected_binding_identity, std::move(slots),
        std::move(rounds));
}

HonestOwnerTwoRoundProductionAuthority::
HonestOwnerTwoRoundProductionAuthority(
        measurement::RunBinding binding, Digest selected_binding_identity,
        std::array<SlotProduction, 12> slots,
        std::array<RoundProduction, 2> rounds)
    : binding_(std::move(binding)),
      binding_identity_(selected_binding_identity),
      slots_(std::move(slots)), rounds_(std::move(rounds)) {
    validate_retained();
}

HonestOwnerTwoRoundProductionAuthority::
HonestOwnerTwoRoundProductionAuthority(
        HonestOwnerTwoRoundProductionAuthority&& other) noexcept
    : binding_(std::move(other.binding_)),
      binding_identity_(other.binding_identity_), slots_(other.slots_),
      rounds_(other.rounds_), live_(other.live_.exchange(false)) {}

void HonestOwnerTwoRoundProductionAuthority::validate_retained() const {
    need(live_.load() && exact(binding_identity_, binding_identity(binding_)));
    for (unsigned index = 0; index < slots_.size(); ++index) {
        const auto& value = slots_[index];
        const unsigned expected_round = index / 6 + 1;
        const unsigned expected_owner = (index % 6) / 2;
        const unsigned expected_slot = index % 2;
        need(value.round == expected_round &&
             value.owner == expected_owner &&
             value.output_slot == expected_slot &&
             nonzero(value.accepted_history_identity) &&
             nonzero(value.source_worker_identity) &&
             nonzero(value.output_verifier_identity) &&
             nonzero(value.crypto_bridge_identity));
        if (index > 0)
            need(exact(value.accepted_history_identity,
                       slots_[0].accepted_history_identity));
        validate_common(
            binding_, binding_identity_, value.accepted_history_identity,
            value.generation_identity, value.round, value.owner,
            value.output_slot, value.invoice_index, value.invoice);
        need(nonzero(value.public_nullifier));
        validate_output_row(value.output);
        need(exact(value.statement_identity, statement_identity(
             binding_identity_, value.accepted_history_identity,
             value.generation_identity, value.source_worker_identity,
             value.output_verifier_identity, value.crypto_bridge_identity,
             value.round, value.owner, value.output_slot,
             value.invoice_index, value.invoice, value.public_nullifier,
             value.output)));
        const auto& round = rounds_[expected_round - 1];
        need(exact(round.projection_identity,
                   binding_.projections[expected_round - 1]) &&
             exact(round.owner_nullifiers[expected_owner],
                   value.public_nullifier) &&
             exact(round.owner_slot_outputs[expected_owner * 2 +
                                            expected_slot],
                   value.output));
        if (expected_slot == 1)
            need(exact(value.public_nullifier,
                       slots_[index - 1].public_nullifier));
    }
    for (const auto& round : rounds_) {
        for (unsigned left = 0; left < round.owner_nullifiers.size(); ++left)
            for (unsigned right = left + 1;
                 right < round.owner_nullifiers.size(); ++right)
                need(!exact(round.owner_nullifiers[left],
                            round.owner_nullifiers[right]));
        for (unsigned left = 0; left < round.owner_slot_outputs.size(); ++left)
            for (unsigned right = left + 1;
                 right < round.owner_slot_outputs.size(); ++right)
                need(!exact(round.owner_slot_outputs[left],
                            round.owner_slot_outputs[right]));
    }
}

void HonestOwnerTwoRoundProductionAuthority::validate_for_terminal(
        const measurement::RunBinding& binding,
        measurement::Classification classification,
        const std::array<std::array<Digest, 3>, 2>& public_nullifiers,
        const std::array<std::array<Output520, 6>, 2>& public_outputs) const {
    validate_retained();
    need(binding_ == binding && binding_.classification == classification &&
         exact(binding_identity_, binding_identity(binding)));
    for (unsigned round = 0; round < 2; ++round) {
        need(exact(rounds_[round].projection_identity,
                   binding.projections[round]) &&
             same_multiset(rounds_[round].owner_nullifiers,
                           public_nullifiers[round]) &&
             same_multiset(rounds_[round].owner_slot_outputs,
                           public_outputs[round]));
    }
}

} // namespace kpb::honest_owner_material
