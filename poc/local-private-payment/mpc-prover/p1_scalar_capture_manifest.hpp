#pragma once

#include <cstdint>
#include <string_view>

namespace kpi::mpc::p1_capture {

enum class ScalarCaptureKind : std::uint8_t {
    Authenticated = 1,
    Randomness = 2,
};

// Every non-linear scalar result or fresh authenticated random value in the
// selected source closure has one immutable call-site identifier. There is no
// unlabelled overload. Linear field/group operations are reconstructed from
// these values, the captured MAC-key share, and the separately bound public
// model/query store.
enum class ScalarCaptureSite : std::uint16_t {
    OwnerDdnntRandomV = 1,
    OwnerDdnntProductU = 2,
    OwnerDdnntTripleS = 3,
    OwnerDdnntTripleR = 4,
    OwnerDdnntTripleW = 5,
    OwnerDerivedInput = 6,
    TraceWitnessRandomBit = 7,
    TraceBitAddGenerate = 8,
    TraceBitAddPropagate = 9,
    TraceBitAddFinalize = 10,
    TraceWitnessBufferedProduct = 11,
    TraceWitnessNonzeroAccumulate = 12,
    TraceWitnessNonzeroSquare = 13,
    TraceWitnessReduction = 14,
    FinancialAssignmentEquality = 15,
    FinancialAssignmentResidual = 16,
    FinancialAssignmentNonzeroAccumulate = 17,
    FinancialAssignmentNonzeroSquare = 18,
    StreamedHProduct = 19,
    FinancialProofMaskR = 20,
    FinancialProofMaskS = 21,
    BeaverTriple = 22,

    AuthFftConstraintProduct = 23,
    AuthFftNonzeroAccumulate = 24,
    AuthFftNonzeroSquare = 25,
    AuthFftReduction = 26,
    AuthFftHProduct = 27,
    BatchedAssignmentResidual = 28,
    BatchedAssignmentNonzeroAccumulate = 29,
    BatchedAssignmentNonzeroSquare = 30,
    ToyProofMaskR = 31,
    ToyProofMaskS = 32,
    PackedAssignmentResidual = 33,
    PackedAssignmentNonzeroAccumulate = 34,
    PackedAssignmentNonzeroSquare = 35,
    PackedProofMaskR = 36,
    PackedProofMaskS = 37,
    FullproofControlProduct = 38,
};

inline constexpr std::string_view SCALAR_CAPTURE_MANIFEST = R"MANIFEST(KPB_P1_SCALAR_CAPTURE_MANIFEST_V1
1|randomness|owner-ddnnt-random-v|selected
2|authenticated|owner-ddnnt-product-u|selected
3|authenticated|owner-ddnnt-triple-s|selected
4|authenticated|owner-ddnnt-triple-r|selected
5|authenticated|owner-ddnnt-triple-w|selected
6|authenticated|owner-derived-input|selected
7|randomness|trace-witness-random-bit|selected
8|authenticated|trace-bit-add-generate|selected
9|authenticated|trace-bit-add-propagate|selected
10|authenticated|trace-bit-add-finalize|selected
11|authenticated|trace-witness-buffered-product|selected
12|authenticated|trace-witness-nonzero-accumulate|selected
13|authenticated|trace-witness-nonzero-square|selected
14|authenticated|trace-witness-reduction|selected
15|authenticated|financial-assignment-equality|selected
16|authenticated|financial-assignment-residual|selected
17|authenticated|financial-assignment-nonzero-accumulate|selected
18|authenticated|financial-assignment-nonzero-square|selected
19|authenticated|streamed-h-product|selected
20|randomness|financial-proof-mask-r|selected
21|randomness|financial-proof-mask-s|selected
22|authenticated|beaver-triple|selected
23|authenticated|auth-fft-constraint-product|nonselected
24|authenticated|auth-fft-nonzero-accumulate|nonselected
25|authenticated|auth-fft-nonzero-square|nonselected
26|authenticated|auth-fft-reduction|nonselected
27|authenticated|auth-fft-h-product|nonselected
28|authenticated|batched-assignment-residual|nonselected
29|authenticated|batched-assignment-nonzero-accumulate|nonselected
30|authenticated|batched-assignment-nonzero-square|nonselected
31|randomness|toy-proof-mask-r|nonselected
32|randomness|toy-proof-mask-s|nonselected
33|authenticated|packed-assignment-residual|nonselected
34|authenticated|packed-assignment-nonzero-accumulate|nonselected
35|authenticated|packed-assignment-nonzero-square|nonselected
36|randomness|packed-proof-mask-r|nonselected
37|randomness|packed-proof-mask-s|nonselected
38|authenticated|fullproof-control-product|nonselected
)MANIFEST";

// sha256(SCALAR_CAPTURE_MANIFEST), checked by source controls and at stream
// construction before the HELLO is emitted.
inline constexpr std::string_view SCALAR_CAPTURE_MANIFEST_SHA256 =
    "5e6903569bc71cbfb5549b369b79a19ecda6686dc4ab25fca0d161c6e1527b6b";
inline constexpr std::uint64_t SELECTED_SCALAR_SITE_BITMAP =
    (std::uint64_t{1} << 22) - 1;

constexpr ScalarCaptureKind scalar_capture_kind(ScalarCaptureSite site) {
    switch (site) {
        case ScalarCaptureSite::OwnerDdnntRandomV:
        case ScalarCaptureSite::TraceWitnessRandomBit:
        case ScalarCaptureSite::FinancialProofMaskR:
        case ScalarCaptureSite::FinancialProofMaskS:
        case ScalarCaptureSite::ToyProofMaskR:
        case ScalarCaptureSite::ToyProofMaskS:
        case ScalarCaptureSite::PackedProofMaskR:
        case ScalarCaptureSite::PackedProofMaskS:
            return ScalarCaptureKind::Randomness;
        default:
            return ScalarCaptureKind::Authenticated;
    }
}

constexpr bool selected_financial_scalar_site(ScalarCaptureSite site) {
    const auto value = static_cast<std::uint16_t>(site);
    return value >= 1 && value <= 22;
}

constexpr bool valid_scalar_capture_site(ScalarCaptureSite site) {
    const auto value = static_cast<std::uint16_t>(site);
    return value >= 1 && value <= 38;
}

} // namespace kpi::mpc::p1_capture
