# ADR-0058: Private full-note exits without commitment appends

**Status:** Accepted for a separate unfunded capacity experiment; not a change
to any existing instance or a production architecture decision.
**Date:** 2026-10-23 UTC. Baseline `5aaf99532d8714e510d421102df719f60f54d073`.
**Origin:** [RFC-0024](../rfc/0024-independent-private-payment-settlement-and-recovery.md).

## Problem, evidence and alternatives

The original compact relation permits no commitment append only when the whole
pool reserve becomes zero. An owner withdrawing while another claim remains
must append two commitments. At physical cursor65535 this can safely reject
and strand a private exit. The new
[design and branch induction](../../research/next-session/independent-payments/exits/DESIGN.md)
and original-policy supplied-context native rejection identify the exact
boundary. The actual native failure is before the private verifier, rather than
an invented missing prover or a fee-only failure.

Compare a no-append full-note private exit, deeper trees, epoch/accumulator
replacement and revealing/admin fallbacks. Select the first as the smallest
experiment that resolves this specific finite-tree dependency. Deeper trees
move the boundary; epochs need authenticated old claims/spentness/recovery;
REVEAL sacrifices disclosure and an admin exit violates the invariants.

Reuse established separate spend/output-count behavior, SHA256/HMAC positioned
nullifiers, indexed spentness, BN254 Groth16 and the existing exact native
state/payout checks. The source lane refreshes current Kaspa/Toccata/vProgs/
research and Orchard/Aztec/RAILGUN/Monero/MWEB comparisons. These analogies do
not import their consensus, soundness or availability properties. Independent
adversarial branch/design review completed before the new relation is written.

## Decision

1. Use only the new explicitly unfunded capacity profile
   [PUBLIC-INSTANCE.json](../../research/next-session/independent-payments/exits/PUBLIC-INSTANCE.json),
   trial `a5ce95a4-22dc-4b9c-bd29-7a38c5b2a3a2`,
   D `d55d006a9bb253963db4f4e44495e60333df9fcc83c1c3ae220806d0f326a0bb`.
   Public profile SHA256 is
   `f2ba0670445ee73c73268e62d0750bc49cae9ff31b389cb3bf0aafb11aae1532`.
   Retain all old programs, relations, domains, parameter bytes and trials.
2. In the new compact relation, mode0 means a full-input private cashout with
   no new commitments. Require payoutP>0, sumIn=P+fee, and every output-witness
   byte including rho zero. Carry CMroot/cursor and bind canonical zero output
   metadata/digest and SHA256(528 zero ciphertext bytes). Preserve every input
   membership/ownership, bounded amount, fee, original real/dummy NF and complete
   Auth528-digest constraint.
3. Distinguish no_append=(mode0) from terminal=(Rprime=0). Terminal implies
   no_append; no_append may retain reserve backing another user. Native output
   count and immutable continuation depend on Rprime. A continuation retains
   exact remaining reserve/state/policy; native payout amount/destination,
   current outpoint, reserve conservation and both sequential current-NF
   absence/update proofs stay mandatory. Never infer continuation from mode.
4. Keep mode2 private change and mode32/P0 wide appends unchanged except for the
   new domain/parameters. Preserve fixed compact matrices across ordinary
   append, continuing no-append and terminal no-append. Generate fresh compact
   and wide development parameter sets after code/CS review; old wide parameters
   are incompatible with the new domain and are not a usable substitute.
5. Establish reserved NF capacity by valid-history induction. For physical CM
   cursor n, NF count m including the sentinel and semantic outstanding positive
   note count U, m+2U<=2n+1. GN starts(1,1,1); ADMIT adds at most one positive
   note per slot with no NF. Each private action consumes r>=1 positive real
   notes, inserts two NFs and creates k<=delta positive notes in delta appended
   slots: delta(m+2U)=2-2r+2k<=2delta. No-append has delta0 and k0. REVEAL
   consumes one positive note and inserts one NF, decreasing the left side.
   Alignment gaps/dummy outputs count as physical slots, not liabilities. Thus
   U>=1 implies m+2<=2n+1<=131071 for n<=65535. No live-note count is published,
   no old CM position is reused and no spentness entry is deleted.

## Validation and limits

Validate exact parser/host boundaries, malformed encodings and direct circuit
counterexamples before setup. A parser rejection is not an UNSAT result.
Independently review the changed matrix and native continuation branch before
generating fresh parameters. Then make genuine privately conserving proofs
and native Full bodies for two sequential exits at CM65535 and NF counts
131067->131069->131071, with reserve2B->1B->0, plus current occupied-NF,
wrong-root, stale-state and payout/fee/reserve tamper controls. Native fees must
be quoted from exact bodies, separately from supplied-context validity.

The boundary prestate is constructed, not a replay of65533 historical proofs
or accepted transactions. Valid-history reachability and the symbolic induction
are explicit premises; no supplied root can self-assert them. Missing public
data remains incomplete. This experiment does not qualify private change at a
full CM tree, future arbitrary fee spikes, inclusion fairness, recovery from
lost ciphertext, independent provider retention or financial privacy. Public
no-append/full-vs-change behavior must be visible to the new privacy observer.

Reconsider the design if any admitted branch violates the induction, a no-append
proof permits change or bypasses ownership, native continuation can release
backing, or a valid remaining claim cannot obtain its two NF slots. Passing
tests/genuine proofs remains implementation evidence, not proof of soundness.

## Bounded experiment outcome

The [closed 232-path result](../../research/next-session/independent-payments/exits/RESULTS.md)
now completes both fresh role setups, four finalized positive shapes, 19 direct
CS controls, three genuine compact proofs, two exact Native Full cashouts,
fresh-current occupied-NF rejection and ten native tamper rejections. CM stays
65535, NF advances131067->131069->131071 and reserve2B->1B->0. The first
cashout retains the other claim's exact backing. Both selected compact modes
and ordinary compact append share the same finalized matrix. Independent
source/parameter/proof/body/financial joins and the finite inventory pass.

This resolves the tested no-append dependency under the stated valid-history
premises. The constructed prior state is not accepted history; original-backup
recovery for this new instance, full-tree partial change, future fee conditions
and incorporation into a fresh live wrapper remain distinct work.
