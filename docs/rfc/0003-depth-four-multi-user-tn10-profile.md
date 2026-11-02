# RFC-0003: Depth-four multi-user TN10 trial profile

**Status:** Accepted for one bounded TN10 experiment

**Date:** 2026-11-01

## Context

The executed full-drainage experiment successfully used the opt-in depth-four
wallet relation from ADR-0018. Its exact public identity is:

```text
domain:   5e9328951d8235750f7108717773bf56357763b5c7f30d800178a877106b7528
verifier: 2460a0b13c2afa27e3c739239b8de4772afd035f417f1a4f615168be9c889086
```

The domain is the SHA-256 of
`KPI/LOCAL-NO-FUNDING/native-KAS/private-note-experiment-depth4-v1`.
ADR-0018 explicitly excludes TN10. Those proofs therefore cannot be broadcast as
a funded trial.

The current native bridge is a different profile. `private-note-chain/common`
enables `tn10-rehearsal`, its guest pins verifier
`d3c179aae5c2c6c013b1de1da5ad4412e4b2c8bae7288c0b9d85e0c986b5a3ec`,
and `private-native` hard-codes the same pins and fixture targets. Its genuine
receipts prove the older depth-two relation and cannot verify the executed
depth-four operations.

This is an indispensable proof/domain boundary, not a funding or RPC problem.
No TN10 funding or broadcast may proceed by relabelling the local domain or
reusing an old receipt.

## Goals / non-goals

Goals:

- define the smallest opt-in trial profile that can replay the executed
  two-deposit/three-payment/five-exit lifecycle on TN10;
- keep exact domain, verifier, guest image and native settlement bindings;
- preserve user-held authorization, integer-sompi conservation, atomic
  nullifiers, permissionless exit construction and zero final user liability;
- retain a fresh one-command unfunded identity per failed trial attempt.

Non-goals:

- production parameters, mainnet, a token, merge, MPC, batching policy, delays,
  locks, privileged withdrawal keys or a capacity increase beyond depth four;
- claiming that a funded payout proves privacy or cryptographic correctness;
- modifying or superseding the historical depth-two/local evidence.

## Constraints

- Preserve every invariant in `SECURITY-INVARIANTS.md`.
- A new TN10 domain requires fresh wallet proofs and a fresh verifier/setup. The
  executed local proofs are controls, not reusable settlement authorization.
- The outer guest and native covenant must pin that exact verifier/domain and
  bind accepted lane activity, old/new state, all nullifiers, exit destinations,
  reserve outpoints and payouts.
- Every owner must recover from its own backup and public authenticated data.
  Services may halt progress but may not gain spend/exit authority.
- Five public exits must be paid and reconciled; zero private liability alone
  does not discharge unpaid exits.

## Options / proposed direction

### A. Relabel the local profile

Rejected. Its domain explicitly says `LOCAL-NO-FUNDING`, and the native guest
does not pin its verifier. Relabelling would invalidate the evidence boundary.

### B. Reuse the historical depth-two native receipt

Rejected. The verifier, domain, Merkle relation, operations, state and journal
are different. Receipt validity for the old program cannot authorize this flow.

### C. Opt-in depth-four TN10 trial profile

Accepted and implemented locally:

1. Add a distinct `tn10-full-drainage-depth4-v1` wallet feature/domain. Keep it
   compile-time incompatible with the local depth-four and old TN10 profiles.
2. Generate a fresh experimental setup and record compressed/uncompressed VK,
   exact hashes and setup boundary.
3. Add an opt-in profile through `private-note-chain/common`, its guest pins,
   `private-native/common`, host/proof pins and target compiler. Default and
   historical targets remain byte-for-byte unchanged.
4. Re-execute the selected wallet world under the new domain with fresh native
   payout keys. Do not translate old operations.
5. Build a fresh guest image, run complete CPU execution, and independently
   verify exact journals before any outer proof or funding.
6. Produce and independently verify genuine Succinct receipts for every native
   settlement batch, then rehearse permission issuance/payout locally with those
   receipts before TN10.

## Minimum settlement schedule

The present guest permits one permission-producing exit per batch. Existing
measurements put one wallet proof verification near 44-47M user cycles and cap a
batch at 160M. The protocol ordering and retained cycle measurements establish a
seven-receipt lower bound:

1. register both deposits and apply the first three wallet operations;
2. apply the remaining two payments plus exit 1;
3. reconcile payout 1 plus exit 2;
4. reconcile payout 2 plus exit 3;
5. reconcile payout 3 plus exit 4;
6. reconcile payout 4 plus exit 5;
7. reconcile payout 5 and confirm zero principal liabilities.

Five exits require five ordered permission-producing batches because only one
exit may be pending. The five earlier wallet operations need two proof-capacity
windows, and the last payout requires one final batch. Exact CPU execution
measured batches 1-7 at 140,115,121; 139,735,495; 46,274,838; 46,443,318;
46,599,013; 46,934,007; and 2,850,602 user cycles respectively. Every journal
matched and every target remained below 160M. Payout reconciliation plus the
next exit also passed the exact local native transition and script checks.

## Security implications

- **Inflation/unauthorized payout:** each native deposit output must register
  once; every private credit, liability, pending exit, reserve debit, permission
  rent/refund and recipient output must reconcile exactly.
- **Double spend:** all current nullifiers remain globally checked across
  batches. Exits prepared at one historical membership root remain subject to
  current-nullifier state when applied.
- **Domain/verifier replay:** local depth-four, old TN10 and new TN10 profiles
  must reject each other's proofs, states and receipts.
- **Reorg/concurrency:** each settlement must re-read selected-chain ancestry and
  rebuild from the last accepted checkpoint. Host success flags cannot advance
  state.
- **Dependency loss:** wallets retain secrets/backups; authenticated public
  history, parameters, software and exact guest/VK pins must remain independently
  available. Missing proving infrastructure is a liveness failure only.
- **Atomicity:** a failed second input, payout or settlement must not partially
  insert nullifiers, discharge liabilities or move reserve principal.

## Privacy implications

The local run demonstrated two compatible gross histories only under its bounded
known-owner/service observers. The strong observer still recovered one history.
TN10 adds public fees, UTXO structure, selected-chain timing, settlement grouping,
RPC/broadcaster metadata, deposit and payout keys, and possibly distinctive
seven-batch activity. These are additional evidence, not presumed harmless.

A funded trial must rescore its actual public transcript. Receipt verification
and successful payouts do not prove ordinary-user anonymity or equal likelihood
of the two chosen histories.

## Operational implications

The local RTX 3070 has 8 GiB VRAM. The original po2-20 batch-1 attempt failed a
1,728,053,248-byte CUDA allocation and is retained. Pinned RISC Zero source
documents `segment_limit_po2`; using po2 19 for batches 1-6 reduced sampled peak
VRAM to 6,213-6,229 MiB without changing the guest, input, journal, program
image, JOIN control, verifier or native checks. All six receipts completed in
181.541-544.527 seconds each and independently verified. Batch 7 retained po2 16.

The receipt-backed local rehearsal passed every exact settlement/issuance/payout
script and zero terminal accounting. Paid proving is no longer required for this
trial. Actual-chain inputs will still require fresh receipts produced locally;
the retained local receipts cannot authorize a different TN10 transcript.

## Evidence / experiments

- `research/full-drainage-executed-lifecycle-2026-11-01/`: two genuine wallet
  worlds, 20 proofs, eight backup restores, ten exits, zero final principal
  liability, local fixtures only.
- ADR-0018: depth-four domain is local and unfunded.
- `poc/private-native/`: old depth-two pinned native lifecycle and explicit
  pending genuine-receipt/TN10 boundary.
- `poc/private-note-proof/gpu-2026-10-18/`: one genuine old-profile Succinct
  receipt and measured L40S resources/cost.
- `research/full-drainage-executed-lifecycle-2026-11-01/tn10-depth4-preparation/`:
  fresh profile, 20 wallet proofs, seven exact native/CPU targets, seven genuine
  new-profile receipts, independent controls, complete receipt-backed rehearsal
  and the retained original local GPU OOM.
- Official heads rechecked 2026-11-01: rusty-kaspa `4edcbbccb449...`, docs
  `0ac77d043a8...`, KIPs `e4ae2332117...`, vProgs `f9b84a863a7...`.

These are implementation and feasibility facts, not a security review.

## Objections / unresolved questions

- The bounded experiment retains seven settlements; reducing that count would
  change the reviewed one-pending-exit state machine and is outside this trial.
- Local native ordering confirms payout reconciliation and the next exit can
  share one batch. Actual selected-chain behavior remains untested.
- Can public history supply every wallet's recovery data after pruning/reorg, or
  is an independently retained archive still required?
- Does actual TN10 fee/rent funding create an identity link that dominates the
  wallet-layer ambiguity?
- Is the based-app/native shared-state route still the minimum after measured
  contention and receipt cost, or would an inline covenant transition be safer
  for this narrow trial?

## Decision criteria

Accept only after:

1. cross-profile proof/state/receipt rejection and all adversarial controls pass;
2. complete CPU execution of the exact native capture schedule stays within
   frozen limits;
3. every genuine receipt independently verifies and the actual native scripts
   locally accept the exact settlement/payout while rejecting underpayment,
   diversion and replay;
4. fresh-identity creation, funding, broadcast, selected-chain confirmation,
   service-loss recovery and zero final principal accounting are rehearsed end
   to end; and
5. the actual transcript is rescored without weakening the strong observer.

Reject or revise if any step requires an old receipt, local-only domain,
privileged exit, unpaid liability, weakened root/nullifier check, retained user
balance, or unbounded paid infrastructure.

## Outcome

Accepted by [ADR-0019](../adr/0019-depth-four-multi-user-tn10-trial.md) for one
bounded Testnet-10 experiment. Acceptance authorizes implementation of the
separate profile; it is not evidence that CPU calibration, genuine receipts,
funded settlement, privacy or production safety succeeded.

