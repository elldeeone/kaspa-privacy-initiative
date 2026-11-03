# RFC-0022: Private cashout and receiver-driven recovery

**Status:** Research implementation and falsifiable experiments in progress.
**Date:** 2026-10-23 UTC. Baseline `63f494053b743ac9bfbd2d1842f69e0f806ef8e3`.

## Remaining product problem

RFC-0021 completes native test-KAS payment mechanics through both confirmed
payouts. Its ordinary revealing exit publishes the selected note/CM/NF credential
and native key; a chain observer can link historical private outputs to cashout.
Recovery still receives an operator-prepared archive and intended-value metadata.
Neither result establishes a complete financially private, independently
recoverable payment system.

This work addresses those two blockers directly. Preserve native KAS,
SECURITY-INVARIANTS, all adopted privacy/fee/resource targets, prior failed
measurements and every funded instance. Source/reuse inspection covers current
official Kaspa/Toccata/vProgs/research and mature privacy protocols before new
proof or withdrawal implementation. No primitive, token or admin exit is added.

## Recovery experiment

ADR-0049 selects public instance configuration, fresh network discovery,
incremental verified replay and separate seed-only ownership/signing. Recover
without a supplied operation list, snapshot, amount map, payer export or saved
exit. Start with the completed real trace, then exercise missing data, pruning,
forks, endpoint loss and current-head changes. A fresh unspent service-loss
rehearsal is stronger evidence and remains required before claiming that path.
Data availability, user-pinned instance identity, validating-node trust and
independent consensus are separate obligations.

The implemented network fetch, replay and approved policy template currently
support the old Auth484/KPX2 program. The new Auth528 program has a separate
unfunded native lifecycle; its network-recovery adapter is not integrated.
Supporting its script in the generic signer alone does not close that gap.

## Private cashout experiment

Study an established join-split public value balance: a shared private action
proves hidden owned inputs and private change, with explicit native public payout
and exact destination. Bind actual state/outpoint, reserve, fee, payout, successor,
CM/NF updates and ciphertext hash. Require a fresh domain/matrices/setup/VK and
immutable native policy; no existing pool is migrated. Keep proofless owner
REVEAL only as an explicitly consented privacy-degrading fallback.

Hiding note openings does not hide public native payout amounts or eliminate
prior/timing/conservation attacks. The proof requires the payout key to differ
from every real consumed note's emergency native signing key. The wallet remains
responsible for destination freshness, control and curve validity; delivery and
incoming keys are separate fields. Complete-cashout observation, collusion, sender and
recipient identity/relationship/value attacks remain in the horizon. The old
21.0977% prior result still fails the unchanged 20% amount gate.

The direct verification floor already prevents a 10-KAS two-recipient payment
plus two independent proof-private exits from satisfying the 2% lifecycle target:
three verifications cost at least 44,250,000 sompi at the reference rate, or
22,125,000 per recipient before other costs. This is an architecture constraint,
not a CPU bottleneck. Prototype privacy improvement without mislabeling it an
economically qualified solution or pooling independent users' private witnesses.

## Evidence order

1. Freeze source-grounded byte/trust contracts and attack/observer boundaries.
2. Demonstrate the existing exit's exact chain-byte channel as a known-pilot
   diagnostic; keep blind population qualification separate.
3. Independently fetch and replay the completed real pool, then recover using
   only one owner backup in an isolated process. Retain data/fork failures.
4. Implement and adversarially check the new private payout relation and native
   policy, including partial change and terminal capacity. Freeze positive and
   genuine proof-replay/current-context negatives before execution.
5. Price complete entry/payment/all-cashout routes. Run prospectively frozen
   privacy comparisons through individual withdrawals and complete drainage.
6. After the entire local path works, use fresh testnet identities for any newly
   authorized live rehearsal, through confirmed native payouts. A local proof,
   synthetic population or multiple RPC assertions is not general privacy,
   independent consensus, durable DA or production qualification.
