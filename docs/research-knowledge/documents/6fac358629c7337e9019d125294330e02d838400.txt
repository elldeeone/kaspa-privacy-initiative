# RFC-0026: Owner-private multiparty construction

**Status:** Open. **Date:** 2026-10-24 UTC.
**Source baseline:** b7b41ab066807d7859499b3491a663ab110fedf9.

## Question and existing failures

Can an established construction assemble separate owners' private payments
without disclosing unrelated input/output groupings or private witnesses to
the assembler? Current W publicly retains each component's output partition.
Hiding only its final public array would not remove the assembler's transcript.
The original observer, prior/singleton failures and qualification thresholds
remain unchanged; no cryptography defeats an already-too-strong price prior.

The [previous decision input](../../research/next-session/independent-payments/privacy-next/DECISION-NEXT.md)
compares private outer records, separate spend/output binding and MWEB. The new
[source/API construction investigation](../../research/next-session/private-construction/CONSTRUCTION.md)
traces actual PCZT builders, individual blinding exposure and ValueShuffle.
Its [independent review](../../research/next-session/private-construction/REVIEW.md)
keeps source facts separate from proposed KAS adaptation.

## Alternatives

1. Reuse an all-witness Orchard/Sapling builder: existing high-level PCZT proving
   and finalization interfaces can require other owners' private data. A single
   builder's shuffling is not owner-private multiparty construction.
2. Publish each owner's value-blinding contribution: this can create an exact
   commitment subset certificate linking that owner's inputs and output group.
   Aggregating the final signature does not erase earlier exposed shares.
3. Study established ValueShuffle confidential output mixing plus privately
   masked blinding aggregation and final exact-body authorization. This is a
   concrete protocol family, not a drop-in KAS implementation or a newly
   selected cryptographic relation. Existing Decred/DC-net APIs must support
   the necessary complete message and accountability contract; a20-byte
   fixed-denomination API alone does not establish that.

## Smallest decisive experiment

[ADR-0061](../adr/0061-construction-api-and-partition-falsification.md) selects
only source/API/real-curve feasibility controls. Call actual maintained APIs
where possible to exercise absent-foreign-witness/finalization failures before
proof generation. Use public synthetic commitment fixtures on an existing
implementation's curve to reproduce the per-owner subset certificate and
identify the exact information its attack requires. Do not implement new MPC,
new signatures, a new note circuit or a KAS privacy subsystem in this gate.

Freeze exact source/API versions, message/knowledge tables and attack/control
definitions before the run. Retain failed builds and unavailable API seams.
No heldout privacy sample, hidden owner truth, wallet backup, current KAS PK or
financial proof is required. A missing exact attack input is not an anonymity
proof, and ordinary arithmetic alternatives are not realizable owner worlds.

## Selection criteria and unresolved obligations

An eventual protocol must specify who constructs every input/output commitment,
who knows each opening/blinding/map, how exact body/fees and global conservation
are authorized, and how original NFs/current state/reserve/native payouts are
bound without new privileged authority. It must keep one-owner private fallback
and backup recovery after abortion/coordinator loss, and explicitly state
non-collusion, message anonymity, honest-participant and retention assumptions.
Malformed/omitted/duplicated outputs and stale/replayed state must be rejected.

Complete output-tuple carriage, secure blinding aggregation, compatible binding
signature suites, native proof costs and transparent entry/exit linkage remain
open until concretely implemented/reviewed. A new KAS circuit requires its own
ADR and source-backed contract; identifying ValueShuffle does not select one.

[ADR-0062](../adr/0062-existing-engine-private-field-sum.md) selects the next
bounded gate: an existing malicious arithmetic MPC engine over exact Jubjub Fr,
followed by the existing commitment-derived Binding verifier. The
[source decision](../../research/next-session/private-construction/full-tuple/sum-review/DECISION.md)
records the executable API candidate and archived SumDC limits. This selects
no KAS relation, anonymous tuple protocol or retry state machine. Those
financial/privacy obligations remain open even if the sum API works.

The [actual component gate](../../research/next-session/private-construction/full-tuple/sum-api/RESULTS.md)
passed: stock MASCOT returned the exact field sums, and its actual first result
verified with the commitment-derived Binding API. **The owner-private protocol
is not built.** The installed action proof still binds each owner's inputs to
its ordered output group. The [next construction decision question](../../research/next-session/private-construction/full-tuple/NEXT-CONSTRUCTION.md)
therefore calls for a second-pass design review and an ADR selecting separate
spend/output statements, global commitment conservation, exact-effect authority
and safe disclosure/retry rules before implementation. The proposed next useful
execution is one genuine unfunded assembled financial body, not another
standalone sum or byte-carriage benchmark. No new relation, setup or adaptation
is accepted by this open question.
