# Private exits at capacity: design and frozen obligations

Status: accepted for the separate unfunded experiment under ADR0058 after independent adversarial design review; fresh setup remains blocked pending implementation/direct-CS review. Existing policy/prover/parameters/funded instances remain unchanged. This experiment uses only public deterministic DO_NOT_FUND canaries, supplied UTXO contexts and fresh development parameters. No chain-currentness, accepted-history, privacy, setup honesty or production claim follows.

## Problem and decisive baseline

ADR0057 binds mode0 iff the entire native reserve becomes zero. A private exit while other liabilities remain therefore appends two CM slots. At CM cursor65535, the aligned append start is65536 and next cursor65538 exceeds65535, so such an exit fails even if every owner can prove their own valid claim and NF space remains. A terminal single-owner exit can omit CMs but cannot solve the multi-owner case. REVEAL is disclosure and is not accepted as the private fallback.

The first supplied-context baseline constructs two positive unspent notes at the CM boundary, attempts a fully conserving mode0 exit with Rprime>0 and records the official native rejection before G16. A matched one-note terminal control checks that mode0 with Rprime=0 reaches G16. Constructed state is a boundary fixture, not a replayed accepted-chain history.

## Minimal candidate and rejected alternatives

Select for review: in a NEW domain/relation/VK/native policy, public mode0 denotes a no-append full-input cashout. All private output fields including rho must be zero. The private equation is sumIn=P+fee; P>0. Both original positioned real and actual-slot dummy nullifiers remain unchanged across roles. CM root/cursor carry exactly; ciphertext hash is SHA256(528 zero bytes), array digest/start/reserved metadata are zero. Native current-NF absence and sequential insertion of both NFs remain mandatory.

Terminal Rprime=0 implies mode0. Mode0 may leave Rprime>=NOTE_FLOOR, with an exact immutable-policy continuation holding all other backing. Whether a continuation exists is controlled separately by Rprime, never by the CM mode. Actual payout amount/destination and complete Auth528 digest stay bound. No-append must not create change. For compact append mode2, alignment, empty-subtree authentication, ordered CM digest and every existing gate remain. Wide mode32 remains P0 only and appends32.

Rejected: silently treating old parameters as new; resetting/evicting NFs; replacing old CM positions; operator/admin exit; REVEAL as a private fallback; minting a rollover claim without exact backing/state binding; pruning ciphertext needed for seed-only recovery; increasing tree depth as the only answer (merely moves the boundary). An unbounded accumulator/epoch redesign is deferred until a demonstrated scaling requirement and complete recovery review.

## Capacity invariant and complete transition cases

Let n be the physical CM cursor, m include the NF sentinel, and U the number of outstanding positive notes (private induction variable, never a published owner map). Require m+2U<=2n+1 with n<=65535 and m<=131071.

Genesis: n=1,m=1,U=1, so equality3=3.
ADMIT: n increases1, m unchanged, U increases1. Both sides increase2.
Private compact/wide append: consume r>=1 real positive notes, append k<=arity positive outputs and advance n by delta>=arity (alignment gaps count toward delta). m increases2; Uprime=U-r+k. Left increases2-2r+2k<=2k<=2delta, so invariant persists, even with dummy outputs.
Private noappend: r>=1, m increases2, U decreases r, n unchanged. Left changes2-2r<=0.
REVEAL (retained disclosure path, not qualifying private recovery): m increases1, consumes one positive note, U decreases1. Left decreases1.
Terminal: exact private conservation and valid-history backing imply no remaining positive liabilities when Rprime=0; no CM append, and the same noappend induction applies. This is not inferred from arbitrary attacker-supplied roots.

Thus when U>=1, m+2<=m+2U<=2n+1<=131071. Every remaining owner can insert two NFs without exhausting the17-level tree, under valid history, sound proofs, real-note single-spend, collision resistance and data availability. The last permitted index is131070; index131071 remains unused by the existing bound. Physical CM indices are0..65534, cursor65535; sparse alignment gaps never count as notes and never require exits. No old CM or NF is deleted.

This guarantees reserved state space for full-note private cashout, not private partial withdrawal/change at a full CM tree, fee affordability, fair inclusion or network availability. The public noappend-vs-change mode leaks behavior and must be included in the new privacy observer. A positive note must retain enough value for the measured fee plus PAYOUT_FLOOR; arbitrary future fee spikes remain an explicit economic limitation.

## Required validation before claims

1. Existing-policy native capacity rejection and terminal G16-seam control.
2. Independent design review of every transition above and immutable continuation.
3. Fresh domain, finalized compact matrix, parser/host controls and direct-CS adversarial controls (not parser errors counted UNSAT). Continuing noappend, terminal noappend and ordinary append share exactly one matrix; old parameter substitution rejects.
4. Fresh development setup. Genuine privately conserving proofs for two sequential exits from a constructed near-full prestate, first with reserve remaining, second terminal; exact Native Full/all-input acceptance, official SDK normalization, fees and zero terminal reserve. NF count reaches131071 while CM remains65535. Constructed prestate never becomes a claim of full accepted history.
5. Native rejection of double-spent NF with a fresh privately valid current-state proof; wrong roots, stale body, missing/corrupt public witnesses, destination/fee/reserve tamper; absence of history reports incomplete, never zero balance or rescue authority.
6. Pure property screen of all transition classes and adversarial induction breaks, plus independent second-pass review.

## Existing-work anchors

- [ADR0056 capacity boundary](../../../../docs/adr/0056-compact-native-batch-fee-screen.md#exit-capacity-and-privacy-boundary) explicitly identifies future no-append proof gates and this invariant.
- [RFC0011 capacity argument](../../../../docs/rfc/0011-two-input-private-payments.md#genesis-and-capacity-must-leave-exits-available) provides the earlier consume-at-least-one/reserved-NF construction; adapt to variable physical cursor/alignment, ADMIT and original NF sharing.
- [ADR0057](../../../../docs/adr/0057-matched-batch-proofs-and-portable-recovery.md) keeps old full-capacity exits open; this new experiment changes that relation only in a new instance.
- Mature designs/current Kaspa sources: refreshed by the sources lane; copy exact pinned references into the experiment source record before crypto implementation. Orchard finite tree handling is not a Kaspa rollover implementation; MWEB PMMR pruning preserves logical positions but cannot recreate missing encrypted receipts. Neither supplies an automatic safe NF reset.
