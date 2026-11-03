# Frozen TN10 threat model — depth-four full-drainage trial

Frozen: 2026-11-01, before funding or broadcast.

## Assets and required outcomes

- Test KAS principal only; no real funds and no mainnet deployment.
- Each private note may move only with its owner-authorized wallet proof.
- Reserve principal equals private liability plus unpaid exits throughout.
- All five exits pay their bound testnet destinations; terminal principal,
  private liability, pending deposits, unpaid exits and permission rent are zero.
- Wallet backups, witnesses and native private keys remain owner-local and out
  of Git, proof jobs and public evidence.

## Actors and trust

- Four logical wallet roles A, B, M and S are controlled by one experiment
  owner. This tests software separation, not independent humans.
- The wallet/prover host may learn public operations and timing but must not
  gain spend or exit authority.
- The outer proof service may disappear or withhold results. That may halt the
  trial but must not authorize value movement.
- TN10 consensus/selected-chain data and the pinned Kaspa/vProgs/RISC Zero
  implementations are assumed for this bounded trial, not proven here.
- Soundness assumes the experimental Groth16 setup toxic waste is unavailable;
  that was not independently demonstrated, so no production-security claim
  follows.

## Frozen observers

1. Public protocol observer: accepted TN10 transactions, UTXOs, amounts, fees,
   scripts, payloads, settlement grouping and timing.
2. Known-owner observer: public transcript plus the frozen deposit-owner and
   exit-owner mappings.
3. Proving/service observer: public operations, batch arrival/order, sizes,
   timing, failures and receipt requests; no wallet secrets or hidden truth.
4. Strong combined observer: all three views, RPC/broadcaster metadata and the
   hidden world label for scoring only.

No observer is granted wallet secrets. No result may infer privacy against a
stronger observer than the one scored.

## Principal attacks and enforced boundaries

- Inflation or unauthorized exit: integer-sompi conservation, authenticated
  deposits, owner proofs, exact reserve/permission/payout accounting.
- Double spend or replay: current nullifier set, exact roots/domain/verifier,
  spent native outpoints and old-state/tip continuity.
- Wrong/stale state: selected-chain capture and exact prior checkpoint are
  required before freezing each target; reorg requires rebuilding from the last
  accepted checkpoint with a fresh trial identity if any broadcast was used.
- Payout diversion/underpayment: the native permission pins recipient, amount,
  selected reserve and permission-rent refund; negative script controls must
  reject mutation.
- Atomicity failure: accepted tracked native consumption that cannot reconcile
  must abort; it cannot be recorded as an ordinary rejected wallet operation.
- Dependency loss: recovery uses an owner backup, authenticated public history,
  pinned parameters/software and an independently checked current root. Missing
  services reduce liveness only.
- Cross-profile replay: local depth-four, historical TN10 and this profile use
  distinct domains, verifier pins, guest images, states and receipts.

## Privacy hypotheses and score rule

The selected H1/H2 histories remain fixed. Score only the actual funded TN10
transcript using the same published-observer rules as the local experiment.
Report exact transcript features that distinguish a history. Do not retune
amounts, batching, observers or thresholds after seeing the result, and do not
claim equal likelihood from absence of a distinguishing rule.

## Stop rules

Stop before funding if the exact guest, VK, journals, CPU cycle limits, local
native scripts or cross-profile controls fail. Stop before broadcast without a
genuine independently verified receipt for that exact target. After a failed or
ambiguous broadcast, never rebroadcast under the same trial identity; create a
fresh unfunded identity and rebuild from current accepted state. Stop and report
if any invariant needs weakening, any principal cannot be reconciled, or paid
compute is indispensable but not authorized.

Passing tests, CPU execution, genuine receipts and confirmed payouts are scoped
implementation evidence only. They are not proof of cryptographic correctness,
privacy, production safety or mainnet readiness.
