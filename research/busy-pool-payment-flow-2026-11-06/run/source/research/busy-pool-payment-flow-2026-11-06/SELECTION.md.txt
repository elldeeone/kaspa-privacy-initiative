# Frozen busy-pool experiment

Selected before executing the experiment, starting from `39666456`.

## Question and controls

Can coordinated arrivals finish without repeated wallet approvals or avoidable
native fees while an independent accepted update makes a real proof stale?
Compare explicit reference admission-first/individual settlement with preserved
oldest-withdrawal priority followed by payment batching. Do not claim either
policy already describes a production service. Same inputs, same actual
competing update, same original approval bytes. Charge shared work to each arm.
Do not silently reuse a receipt unless input, image and journal match exactly.

Use unchanged ADR-0111 program and complete wallet proofs. Initial 40 KAS split
through real payments: Alice to Bob 20, Bob to Carol 10, Alice to Dave 10.
Alice/Bob/Carol each approve a common 10-KAS withdrawal once. Dave pays Alice
2 KAS in the competing update, then queues payments of 1 to Bob, 3 to Carol and
1 to Alice. This uses fifteen of sixteen leaves. Later cash out every remainder
using ordinary named exits, with restored native payout keys. Four separate
wallet processes on one machine, not independent humans or hardened isolation.
Both scheduler continuations ultimately use the same five later named approvals
with distinct fresh native receipts and end with zero reserve/liability. The
reference executes sequentially on the same GPU using the exact shared prefix
and recorded arrivals; its clock includes its own measured branch work. Group
wait starts at the first withdrawal proof. Precomputed competing-proof work and
cold wallet preparation are charged separately. Local registration is identified;
protected registration is retained from earlier work, not claimed as retested.

Accept the competing update 30 seconds into genuine withdrawal proving; prepare
its receipt beforehand on the single GPU and report that work separately.
Start wallet payment preparation at real elapsed offsets 90, 330 and 570 seconds;
record when the actual completed requests enter the queue. No fake time or
assumed invalidation from a merely pending request. Preserve the stale receipt.
If implementation/operational failures require a changed schedule, retain this
selection and record a new attempt before its execution.

## Acceptance and stop rules

All accepted transactions require real complete SDK receipts, genuine compressed
proofs and current native Full validation. No queued/projected operation counts
as settled. Current nullifier, historical-anchor, exact effects, fee caps and
conservation checks remain. A stale transaction must fail at the intended spent
outpoint/current-state boundary. Terminal principal and liability must be zero.
Each wallet restores its own keys and demonstrates spending its actual payout.

Record complete native fees, wallet work, successful and wasted outer proof work,
queue waits and final accounting. Conditional cloud price estimates must remain
separate from measured local usage and unknown service/availability costs. Keep
the existing 2% complete-cost target; do not retune it after observing results.

Freeze privacy views: public chain and supplied contact roles; actual service
request/registration metadata; participant-owned payouts; later named-owner
disclosure. Count payout ownership separately from payment-amount histories.
Research-controller private truth is not observer evidence. If the new harness
does not reproduce protected registration, it must report identified-source
leakage and reuse prior Tor results only with their original scope. No assumed
anonymous shuffle, omitted service metadata or invented privacy success.

One external advance and three queued payments cannot qualify unbounded busy
traffic. Honest queue priority cannot prevent independent current-bank races.
No new circuit, consensus change, real funds or mainnet. A funded testnet trial
is not automatic: first report whether the offline privacy/cost/recovery gates
actually justify it. Preserve failed attempts without relabelling them success.
