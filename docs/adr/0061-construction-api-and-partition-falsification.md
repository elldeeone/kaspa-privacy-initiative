# ADR-0061: Construction API and partition falsification

**Status:** Accepted for bounded source/API/algebra controls only.
**Date:** 2026-10-24 UTC.
**Origin:** [RFC-0026](../rfc/0026-owner-private-multiparty-construction.md).

The [bounded experiment](../../research/next-session/private-construction/RESULTS.md)
completed on actual upstream APIs and Jubjub/RedJubjub: unsupported foreign
witness/trapdoor assembly fails, exposed owner blinding contributions identify
output groups, and correctly aggregated binding verification passes. These
are component controls, not genuine Sapling/KAS financial proofs or a private
constructor. The follow-up exact-field sum is recorded in ADR0062.

## Decision and scope

The owner requests a concrete established owner-private construction. First
falsify unsupported shortcuts using actual upstream builder APIs and existing
curve implementations. New code, if required, is confined to
`poc/private-construction-harness`; source/results live under the separate
`research/next-session/private-construction` path. The independent construction
reviewer must ACK the exact harness source/experiment contract before execution.

1. Pin exact upstream PCZT/proving/finalization source. Exercise the earliest
   relevant actual API error when foreign witnesses or blinding shares are
   absent. If the API cannot be instantiated without parameters/proving first,
   record that seam rather than generating a setup for an already failed
   construction. Source inspection is reported separately from executed errors.
2. Reproduce the per-owner binding-contribution subset certificate with small,
   explicitly public synthetic commitments on an established implementation's
   actual curve. Enumerate the finite candidate output subsets and verify exact
   commitment equality. Freeze the values, attack input knowledge and expected
   control behavior before execution. This is candidate falsification, not an
   attack score for current KAS or an anonymity qualification.
3. Map the established ValueShuffle message flow and available implementation
   seams: confidential full output tuples, private blinding aggregation and
   exact final authorization. Retain width/curve/signature/transport/API gaps.
   Do not truncate authenticated messages, invent a distributed binding suite,
   silently exclude the assembler or implement a new primitive to bridge them.

Use no real keys, backups, private trial truth, KAS PK, proof generation, VM,
GPU, funding or live network transaction. Source/dependency builds use a bounded
light CPU/RAM slot coordinated with the financial-profile lane. No global
toolchain installation or old source modification is needed.

## Rejected shortcuts and trust limits

An all-knowing builder, redaction after proving, a shuffled final output list,
ordinary threshold signing without compatible binding semantics, or exposing
individual blinding sums cannot be assumed to meet the observer. A public
algebra fixture may demonstrate one exact leak; it does not establish security
of a masked alternative. Existing protocol specifications are evidence of their
own construction and assumptions, not proof of a KAS composition.

No original threshold, price distribution, singleton ancestry failure or heldout
result changes. Success in this gate is a precise source/API construction verdict
with retained negative controls. Selecting/adapting a new financial relation,
claiming strong privacy or replacing current fallback requires a later explicit
decision. Stop on an unsupported API or hidden trust assumption; document it.
