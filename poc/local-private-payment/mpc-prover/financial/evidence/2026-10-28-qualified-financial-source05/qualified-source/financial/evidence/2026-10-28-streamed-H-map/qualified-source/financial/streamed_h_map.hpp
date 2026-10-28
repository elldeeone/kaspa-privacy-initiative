#pragma once

#include "../packed/packed_model.hpp"

namespace kpi::mpc::financial {

class PackedValidatedAssignment;
class FinancialValidatedAssignment;

// A witness map is not a validity check. Only the sealed financial assignment
// capability may enter this path, after consuming its context/epoch binding.
// No unchecked assignment span is exposed by the production public interface.
class StreamedWitnessMap final {
    StreamedWitnessMap() = delete;
    friend class PackedValidatedAssignment;
    friend class FinancialValidatedAssignment;

    // Owns at most two domain-sized vectors: A+B, then A+C. A multiplication
    // result chunk is independently capped at4096 authenticated elements.
    static std::vector<AuthScalar> compute(MascotContext& context,
        const packed::PackedModel& model,
        std::span<const AuthScalar> immutable_assignment,
        size_t multiplication_batch = 4096);

#ifdef KPI_STREAMED_H_MAP_PUBLIC_FIXTURE_CONTROL
public:
    // This member exists only in a separately compiled PUBLIC-fixture test
    // binary. All TUs using this interface in that binary must share the flag;
    // financial builders must omit it. There is no runtime enable/skip flag.
    static std::vector<AuthScalar> public_fixture_compute(MascotContext& context,
        const packed::PackedModel& model,
        std::span<const AuthScalar> public_fixture_assignment,
        size_t multiplication_batch = 4096);
#endif
};

}  // namespace kpi::mpc::financial
