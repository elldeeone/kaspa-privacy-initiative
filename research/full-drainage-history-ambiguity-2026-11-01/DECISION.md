# Full-drainage payment-history decision

## Answer

**Yes as a bounded possibility; no as a reliable guarantee.**

After every modeled balance is withdrawn to a known owner, ordinary overlapping
payments can still leave more than one materially different gross payment
history compatible with the same public evidence. The frozen candidate has two:

```text
History 1: A -> M 40m; B -> M 20m; M -> S 10m sompi
History 2: A -> M 30m; A -> S 10m; B -> M 20m sompi
```

Both have the same two deposits, three generic private transfers, five
known-owner exits and zero remaining liability. They differ in a relationship
and an amount, not merely note labels, commitment assignments or event position.

This does not establish ordinary-user anonymity or universal full-withdrawal
unlinkability. When the retained strong observer additionally knows that M paid
S, only History 1 remains. The sparse failure control also remains unique.

## Decisive results

| View | Compatible event sequences | Distinct gross histories | Result |
|---|---:|---:|---|
| protocol-known owner mappings | 12 | 3 | ambiguity possible |
| plausible four-edge contact graph, owners known | 9 | 2 | candidate passes |
| strong observer: S was paid by M | 3 | 1 | ambiguity collapses |
| isolated known-owner control | 1 | 1 | failure control passes |

The unmapped-owner sensitivity view has 972 gross histories, but that larger
number is not used for the decision because payout-owner mappings are plausible
external knowledge.

The model is exhaustive over its frozen finite amount grid; it uses no random
sample or hidden selected truth. See [SELECTION.md](SELECTION.md) and
[MODEL-RESULT.json](MODEL-RESULT.json).

## What changed from the earlier false pass

The earlier experiments supplied unusually constraining workload facts: exactly
two chains, fixed sender groups, one-to-one recipient roles, payment ranges,
checkpoint roles, exit partitions and no other activity. Those facts—not merely
the public shielded protocol—made the payment equations invertible.

The new candidate substitutes ordinary overlapping receipts and payments. That
is a different workload assumption, not a protocol repair. The strong observer
is retained and still defeats the candidate when it knows one decisive edge.
See [OBSERVER-INPUT-AUDIT.md](OBSERVER-INPUT-AUDIT.md).

## Current operation versus merge

The current one-input/two-output transfer is sufficient for the bounded
possibility result. It is not sufficient to consolidate independently received
notes: the witness has one input/path, the statement has one nullifier, and the
ledger applies one economic nullifier.

Consequently, M publicly exits two note values, `30m + 20m`, rather than one net
`50m` value. A hypothetical private `2 -> 1` merge preserves the two candidate
histories and reduces that terminal note-level disclosure to one M exit. It does
not hide M's net withdrawal and does not rescue the sparse or strong-observer
failures.

The smallest proposed capability is therefore a same-authority, two-input,
one-output private merge with two memberships, two distinct nullifiers, exact
integer conservation and atomic application. It is documented—but not approved
or implemented—in [MERGE-PROPOSAL.md](MERGE-PROPOSAL.md). Local source evidence
is in [LOCAL-CAPABILITY-AUDIT.md](LOCAL-CAPABILITY-AUDIT.md).

## Current upstream authority

Current pinned Kaspa documentation describes inline verification for private
local transitions and covenant lineages that can merge, while routing globally
shared state, batching and activity-derived exits toward based-app architecture.
No checked primary source states that expanding shielded note arity itself
requires a Kaspa consensus change. The state layout still determines whether the
complete note-tree/nullifier-set design can remain covenant-local or requires a
coordinated based-app state machine. vProgs remains early/prototype evidence, not
production-readiness evidence.

Orchard, Aztec and RAILGUN provide mature multi-note patterns: per-input
membership and nullifier checks, aggregate balance, authorization and atomic
state transition. They are design analogues, not proof of direct Kaspa
deployability or security. Exact upstream commits and file citations are in
[SOURCES.md](SOURCES.md).

## Decision

1. **Accept:** full drainage does not mathematically force unique payment-history
   recovery in every workload; the candidate provides a concrete counterexample.
2. **Reject:** any claim that current operations guarantee history privacy after
   full drainage, that the two histories are equally likely, or that ordinary
   user privacy has been measured.
3. **Retain:** known payout ownership and the strong observer as required adverse
   views. Do not use the unmapped view as the headline result.
4. **Propose, do not implement:** private merge as the minimal note-consolidation
   capability. Its purpose is reduced exit granularity, not a universal privacy
   fix.
5. **Architecture boundary remains open:** no consensus-change or vProgs
   requirement was found for note arity alone; deployment depends on the chosen
   state and settlement architecture.

No circuit, prover, wallet, runtime or network behavior was changed. No test KAS,
MPC, delay, lock, coordinator, dummy traffic or retained balance was used.
