#include "honest_owner_material_authority.hpp"

#ifdef KPB_HONEST_OWNER_MATERIAL_TEST_SETUP

#include "../../future-recipient/v3/v3_native_authority.hpp"

#include <algorithm>
#include <cstring>
#include <openssl/sha.h>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace kpb::honest_owner_material {
namespace {

using Bytes = std::vector<unsigned char>;

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
    for (unsigned index = 0; index < width; ++index)
        out.push_back(static_cast<unsigned char>(value >> (8 * index)));
}
Digest hash(std::span<const unsigned char> value) {
    Digest result{};
    if (SHA256(value.data(), value.size(), result.data()) == nullptr)
        throw HonestOwnerRefused();
    return result;
}
Digest labelled(std::string_view label, const Digest& binding,
                unsigned round = 0, unsigned owner = 0,
                unsigned slot = 0) {
    Bytes bytes;
    add(bytes, label);
    add(bytes, binding);
    little(bytes, round, 4);
    little(bytes, owner, 4);
    little(bytes, slot, 4);
    return hash(bytes);
}
Digest generation(
        const Digest& binding, const Digest& history,
        unsigned round, unsigned owner, unsigned slot,
        std::uint64_t index, const Invoice208& invoice) {
    Bytes bytes;
    add(bytes, "KPB_HONEST_OWNER_PREGENERATION_V1\n");
    add(bytes, binding); add(bytes, history);
    little(bytes, round, 4); little(bytes, owner, 4);
    little(bytes, slot, 4); little(bytes, index); add(bytes, invoice);
    return hash(bytes);
}
Digest statement(
        const Digest& binding, const Digest& history,
        const Digest& generation_identity, const Digest& worker,
        const Digest& verifier, const Digest& crypto,
        unsigned round, unsigned owner, unsigned slot,
        std::uint64_t index, const Invoice208& invoice,
        const Digest& nf, const Output520& output) {
    Bytes bytes;
    add(bytes, "KPB_HONEST_OWNER_OUTPUT_STATEMENT_V1\n");
    for (const auto* field : {&binding, &history, &generation_identity,
                              &worker, &verifier, &crypto, &nf})
        add(bytes, *field);
    little(bytes, round, 4); little(bytes, owner, 4);
    little(bytes, slot, 4); little(bytes, index);
    add(bytes, invoice); add(bytes, output);
    return hash(bytes);
}
Invoice208 invoice_for(unsigned round, unsigned owner, unsigned slot) {
    Invoice208 result{};
    std::memcpy(result.data(), "KPX3IN01", 8);
    const std::uint64_t index =
        static_cast<std::uint64_t>((round - 1) * 6 + owner * 2 + slot + 1);
    for (unsigned byte = 0; byte < 8; ++byte)
        result[40 + byte] = static_cast<unsigned char>(index >> (8 * byte));
    for (const auto offset : {8U, 48U, 80U, 112U, 144U, 176U})
        for (unsigned byte = 0; byte < 32; ++byte)
            result[offset + byte] = static_cast<unsigned char>(
                1U + ((round * 53U + owner * 17U + slot * 7U + offset + byte)
                      & 0xfeU));
    return result;
}
std::uint64_t index_for(unsigned round, unsigned owner, unsigned slot) {
    return static_cast<std::uint64_t>(
        (round - 1) * 6 + owner * 2 + slot + 1);
}

} // namespace

HonestInvoiceSourceAuthority HonestOwnerMaterialTestFixture::invoice_source(
        const measurement::RunBinding& binding, Digest history,
        unsigned round, unsigned owner, unsigned output_slot,
        std::uint64_t index, Invoice208 invoice) {
    const auto binding_id =
        future_recipient::v3_native::recompute_v3_run_binding_identity(binding);
    return HonestInvoiceSourceAuthority(
        binding, history, round, owner, output_slot, index, invoice,
        generation(binding_id, history, round, owner, output_slot, index,
                   invoice));
}

HonestOwnerOutputAuthority HonestOwnerMaterialTestFixture::output_source(
        const measurement::RunBinding& binding, Digest history,
        unsigned round, unsigned owner, unsigned output_slot,
        std::uint64_t index, Invoice208 invoice, Digest nf,
        Output520 output) {
    const auto binding_id =
        future_recipient::v3_native::recompute_v3_run_binding_identity(binding);
    const auto pregeneration = generation(
        binding_id, history, round, owner, output_slot, index, invoice);
    const auto worker = labelled(
        "KPB_TEST_HONEST_OWNER_WORKER_V1\n", binding_id,
        round, owner, output_slot);
    const auto verifier = labelled(
        "KPB_TEST_HONEST_OWNER_VERIFIER_V1\n", binding_id,
        round, owner, output_slot);
    const auto crypto = labelled(
        "KPB_TEST_HONEST_OWNER_CRYPTO_V1\n", binding_id,
        round, owner, output_slot);
    return HonestOwnerOutputAuthority(
        binding, history, round, owner, output_slot, index, invoice, nf,
        output, pregeneration, worker, verifier, crypto,
        statement(binding_id, history, pregeneration, worker, verifier,
                  crypto, round, owner, output_slot, index, invoice, nf,
                  output));
}

HonestOwnerTwoRoundProductionAuthority
HonestOwnerMaterialTestFixture::two_rounds(
        const measurement::RunBinding& selected,
        const std::array<Projection10685, 2>& projections,
        HonestOwnerTestFault fault) {
    const auto binding_id =
        future_recipient::v3_native::recompute_v3_run_binding_identity(selected);
    const auto history = labelled(
        "KPB_TEST_ACCEPTED_HISTORY_V1\n", binding_id);
    std::array<HonestOwnerTwoRoundProductionAuthority::SlotProduction, 12>
        slots{};
    std::array<HonestOwnerTwoRoundProductionAuthority::RoundProduction, 2>
        rounds{};
    for (unsigned round_index = 0; round_index < 2; ++round_index) {
        const auto* raw = reinterpret_cast<const unsigned char*>(
            projections[round_index].data());
        if (std::memcmp(raw, "KPBAFX01\x01\0\x01\0", 12) != 0 ||
            std::memcmp(raw + 193, "KPBAEF01", 8) != 0)
            throw HonestOwnerRefused();
        const auto* body = raw + 193;
        rounds[round_index].projection_identity =
            hash({raw, projections[round_index].size()});
        for (unsigned owner = 0; owner < 3; ++owner) {
            std::copy_n(body + 404 + owner * 96, 32,
                        rounds[round_index].owner_nullifiers[owner].begin());
            for (unsigned slot = 0; slot < 2; ++slot) {
                const unsigned flat = round_index * 6 + owner * 2 + slot;
                auto& row = rounds[round_index].owner_slot_outputs[
                    owner * 2 + slot];
                std::copy_n(body + 692 + (owner * 2 + slot) * 520,
                            520, row.begin());
                const unsigned round = round_index + 1;
                const auto invoice = invoice_for(round, owner, slot);
                const auto index = index_for(round, owner, slot);
                const auto pregeneration = generation(
                    binding_id, history, round, owner, slot, index, invoice);
                const auto worker = labelled(
                    "KPB_TEST_HONEST_OWNER_WORKER_V1\n", binding_id,
                    round, owner, slot);
                const auto verifier = labelled(
                    "KPB_TEST_HONEST_OWNER_VERIFIER_V1\n", binding_id,
                    round, owner, slot);
                const auto crypto = labelled(
                    "KPB_TEST_HONEST_OWNER_CRYPTO_V1\n", binding_id,
                    round, owner, slot);
                slots[flat] = {
                    .accepted_history_identity = history,
                    .generation_identity = pregeneration,
                    .source_worker_identity = worker,
                    .output_verifier_identity = verifier,
                    .crypto_bridge_identity = crypto,
                    .statement_identity = statement(
                        binding_id, history, pregeneration, worker, verifier,
                        crypto, round, owner, slot, index, invoice,
                        rounds[round_index].owner_nullifiers[owner], row),
                    .round = round, .owner = owner, .output_slot = slot,
                    .invoice_index = index, .invoice = invoice,
                    .public_nullifier =
                        rounds[round_index].owner_nullifiers[owner],
                    .output = row,
                };
            }
        }
    }
    HonestOwnerTwoRoundProductionAuthority result(
        selected, binding_id, std::move(slots), std::move(rounds));
    const auto restate = [&](auto& slot) {
        slot.statement_identity = statement(
            result.binding_identity_, slot.accepted_history_identity,
            slot.generation_identity, slot.source_worker_identity,
            slot.output_verifier_identity, slot.crypto_bridge_identity,
            slot.round, slot.owner, slot.output_slot, slot.invoice_index,
            slot.invoice, slot.public_nullifier, slot.output);
    };
    const auto rebind = [&] {
        result.binding_identity_ = future_recipient::v3_native::
            recompute_v3_run_binding_identity(result.binding_);
        for (auto& slot : result.slots_) {
            slot.generation_identity = generation(
                result.binding_identity_, slot.accepted_history_identity,
                slot.round, slot.owner, slot.output_slot,
                slot.invoice_index, slot.invoice);
            restate(slot);
        }
        for (unsigned round = 0; round < result.rounds_.size(); ++round)
            result.rounds_[round].projection_identity =
                result.binding_.projections[round];
    };
    switch (fault) {
    case HonestOwnerTestFault::None:
        break;
    case HonestOwnerTestFault::WrongRound:
        result.slots_[0].round = 2;
        break;
    case HonestOwnerTestFault::WrongOwner:
        result.slots_[0].owner = 1;
        break;
    case HonestOwnerTestFault::WrongNullifier:
        result.rounds_[0].owner_nullifiers[0][0] ^= 0x80;
        for (unsigned slot = 0; slot < 2; ++slot) {
            auto& value = result.slots_[slot];
            value.public_nullifier =
                result.rounds_[0].owner_nullifiers[0];
            restate(value);
        }
        break;
    case HonestOwnerTestFault::WrongOutputRow:
        result.rounds_[0].owner_slot_outputs[0] =
            result.rounds_[1].owner_slot_outputs[0];
        result.slots_[0].output = result.rounds_[0].owner_slot_outputs[0];
        restate(result.slots_[0]);
        break;
    case HonestOwnerTestFault::WrongProjection:
        result.binding_.projections[0][0] ^= 0x80;
        rebind();
        break;
    case HonestOwnerTestFault::WrongRunBinding:
        result.binding_.trial[0] ^= 0x80;
        rebind();
        break;
    }
    return result;
}

} // namespace kpb::honest_owner_material

#endif
