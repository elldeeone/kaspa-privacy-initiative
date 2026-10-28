# ADR-0074: Restricted-intent private-batch research and fail-closed disclosure

Date: 2026-10-28 UTC.

Status: Accepted for the bounded offline protocol model and implementation
interfaces in [RFC-0030](../rfc/0030-private-batch-construction.md). This selects
no production architecture or financially ready native profile. Existing
funded pools and frozen source/evidence remain unchanged.

## Context

The native one-input/two-output lifecycle works under its measured scope, but
the ledger and constructor still know payment groups. Owner-local signatures
can retain spending authority outside a collaborative prover; the current
one-owner authority component nevertheless signs a complete global packet.
Showing a multi-owner packet to every signer exposes other NFs before final
settlement. Asking a signer to approve a server-provided opaque hash removes
informed exact-effects consent.

The [refreshed primary-source review](../../research/next-session/local-private-payment/privacy-next/PRIVATE-BATCH-SOURCE-REFRESH-2026-10-28.md)
and existing [ADR-0068](0068-offline-owner-consent-aggregation.md) support studying
restricted own-effects consent plus a constrained hidden correspondence.
They do not provide an implemented private prover or eliminate abort/retry
intersection. The existing ABC→ADE counterexample survives complete valid proofs.

## Decision

1. Select one **new research profile** for owner-local restricted-intent
   authorization. Bind the owner's exact NF/CV, two complete approved outputs,
   fee, nonce, exact authenticated head and chain/pool/profile/domain/service
   context. The signing secret never enters the prover. The 1460-byte codec
   in RFC-0030 is the interface; actual circuit hashes and signature checks
   remain required before it can authorize funds.
2. Study a three-owner/three-input/six-output complete aggregate, with private
   independent input/output bijections, per-owner bounded conservation, exact
   native effects and one proof. Three u64 fees use a 66-bit intermediate,
   followed by a native u64 bound. Publish only total fee/Delta and whole tuples;
   no individual owner slots, statement hashes, pair tags or fee allocation.
   Keep each actual per-owner CV/blinding relation in its owner-local component;
   join its canonical private delta to public Delta through the exact integer
   quotient equation in RFC-0030 (`sum(delta_i)=Delta+kQ`, `k` in `{0,1,2}`, `3Q<P`).
   This removes joint curve auxiliaries while retaining every curve, range,
   correspondence and conservation predicate and the proved public CV check.
3. Require qualified private witness construction, authenticated arithmetic and
   complete extended-witness validity before reactive proof openings. Preserve
   the existing MASCOT external input/group-MAC contracts and independent final
   verification. A clear combined witness, host validity bit or semi-honest
   fallback is not this implementation.
4. Reuse the existing **mandatory proved R0 public wrapper** for the public
   CM/NF transition algorithms. The private aggregate proves authorization,
   hidden correspondence, note/CV bindings, conservation and SHA binding of
   the complete 10,364-byte effects. The new R0 guest independently verifies
   that aggregate plus six genuine Output proofs, exact current tree updates,
   public CV balance, counts/capacities and the selected profile/policy, and
   emits the selected journal/projection. The native covenant verifies its
   pinned receipt/image and actual reserve/state/fee/successor effects.
   Public paths are outside the private R1CS but inside this mandatory proved
   composition. A host payload-checker Boolean is never financial acceptance.
5. Select an explicit **fail-closed private-progress policy** within one
   service/history epoch. Persist exact cohort/effect commitments before any
   possibly revealing opening. Refuse overlapping changed cohorts/effects after
   preparation, including after crashes and chain reorgs. This policy can halt
   private progress indefinitely after a colluder Exit or peer loss.
6. Preserve unconditional cryptographic independent Exit and original-seed
   received/change recovery under the new profile. New AK-bound Note.owner
   requires matching Output, Intent/Aggregate, AuthExit, KDF/address and scan
   identities. No new-profile funding before the complete real terminal path
   works. No legacy proof/key/backup compatibility is inferred.

## Alternatives and consequences

| Alternative | Decision / consequence |
| --- | --- |
| Give every signer the complete final packet | Preserves old whole-effects consent but discloses other raw NFs before settlement; rejected for the new mapping target. |
| Approve an opaque coordinator hash | Removes informed owner consent; rejected. |
| Share the old owner_secret | Gives full prover collusion spending authority; rejected. |
| Owner restricted intents plus exact aggregate correspondence | Selected research interface; changes the relation/profile and needs all output/current-state/Exit checks. |
| Public tree updates in a mandatory proved R0 guest | Selected reuse of the existing financial proof boundary; needs a new matching guest/image/native policy and real end-to-end validation. |
| Public tree updates accepted by an ordinary host checker | Does not prove state validity; rejected. |
| Retry disclosed inputs in arbitrary new cohorts | Retains the known intersection counterexample; rejected within the bounded service policy. |
| Freeze independent Exit until peers cooperate | Violates I-8/I-9/I-10; rejected. |
| Accepted reservation/continuation state | Remains a separate architecture option requiring its own disclosure, reserve, cancellation, fee and reorg design. Not selected by this model. |

At most one corrupt server of three plus one colluding wallet is the studied
active view; at least two honest unknown spenders are a workload condition.
Private progress additionally trusts honest service persistence and an
authenticated latest history checkpoint. Loss or rollback of both the journal
and that checkpoint is not detectable by a local hash chain. The final SNARK
does not prove which parties ran it or that no earlier disclosure occurred.
Service affinity is a new privacy/liveness assumption, not financial authority.

This policy **does not resolve unrestricted O-active**, cross-service bypass,
operator history rollback, or private progress using only accepted history
after service loss. Those remain privacy failures/unqualified controls. A safe
halt is measurable lost liveness. No record may turn those outcomes into
anonymity or production-security claims.

## Implementation and validation boundary

The canonical intent codec is an encoding boundary only. The SQLite release
barrier is a runnable durability/information-flow model with clear synthetic
member tokens and opaque synthetic proof bytes. Its external checkpoint is
trusted input. Real NF equality/admission must be computed inside qualified MPC;
real egress still needs complete proof/current-state/effect validation.

Tests must cover fixed encoding/ranges, complete tuple/context binding, missing
history, expected-head rollback, fresh nonce/setup/service bypass, changed
cohorts/effects, crash-after-prepare, crash-after-publication-intent and no
per-owner refusal detail. Preserve the original changed-cohort mapping result.
Model passes establish only tested codec/durability behavior.

Before calling the integrated result complete, obtain genuine multi-owner native
batch acceptance, adversarial financial controls, actual measured allowed views,
original-seed scans, service-loss independent exits and confirmed native payouts.
Full lifecycle fees retain the frozen denominator/target. The existing 2% fee
failure, grouping failures and availability limits remain visible.

No invariant changes, new token, mainnet code, real funds, privileged withdrawal,
production architecture selection or existing evidence reclassification occurs.
