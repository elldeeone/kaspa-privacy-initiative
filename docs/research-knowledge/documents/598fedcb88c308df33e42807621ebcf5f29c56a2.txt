# Frozen common-ledger unrelated-activity experiment

**Freeze date:** 2026-11-01
**Experiment identifier:** `wallet-local-shared-history-v1`
**Repository commit:** `7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1`
**Capacity profile:** ADR-0018 depth four, 16 leaves, distinct local domain

This selection is public observer evidence. Every sampling bound, identity group,
relationship restriction and scheduling rule below is therefore available to the
observer. The exact sampled workload is generated owner-locally and committed by
hash before wallets or operations exist.

Values, policy, observers, attacks, thresholds and stop rules must not be retuned
after workload commitment or observation generation.

## Question

When two unrelated genuine private payment/re-spending chains share one complete
shielded history, does unrelated activity preserve payment ambiguity while target
users withdraw, and does eventual complete drainage undo it?

This is generated same-host local activity, not evidence of independent user
adoption. No dummy user or cover operation is added: every credit, payment,
re-spend and exit is a genuine wallet operation whose owner can recover and spend
or exit its note.

## Public workload policy

Use one ledger and eight independently keyed wallet contexts `A`–`H`.

### Credits

Credit four public deposit fixtures in fixed A/B/C/D order:

| identity | value |
|---|---:|
| A | 900,000,000 sompi |
| B | 800,000,000 sompi |
| C | 700,000,000 sompi |
| D | 600,000,000 sompi |

### Two unrelated chains

- Chain 0 first sender is sampled uniformly from `{A,B}`.
- Chain 1 first sender is sampled uniformly from `{C,D}`.
- First recipients are a uniformly shuffled one-to-one assignment of `{E,F}` to
  chains 0 and 1.
- Second recipients are a uniformly shuffled one-to-one assignment of `{G,H}` to
  chains 0 and 1.
- Public contact edges are every `{A,B,C,D} -> {E,F}` edge and every
  `{E,F} -> {G,H}` edge. The chain sender-group restriction above remains known.

Sample exact integer-sompi payment values:

| chain | P1 range | P2 rule |
|---|---:|---:|
| 0 | uniform `[220,000,000, 500,000,000]` | uniform `[80,000,000, P1-80,000,000]` |
| 1 | uniform `[180,000,000, 400,000,000]` | uniform `[60,000,000, P1-60,000,000]` |

Require only `P2 < P1 < both possible source deposits`; impose no cross-chain
amount inequality or denomination rule. Exact collisions are allowed.

Each chain executes:

```text
selected credited sender --P1--> first recipient + sender change
first recipient --P2--> second recipient + first-recipient change
```

The first recipient restores its owner-local backup and discovers P1 from accepted
public records before re-spending it. Each transfer independently samples payment
output index 0 or 1 uniformly.

### Shared scheduling

Uniformly choose one of the six length-four chain schedules containing two `0`s
and two `1`s while preserving each chain's first transfer before its second.
Operation events are public generic transfers; no public event labels its hidden
chain or stage.

### Cashout checkpoints

Uniformly choose one target chain privately.

1. **`pre-cashout`:** after all four transfers, before any exit.
2. **`target-cashout`:** restore the target chain's first and second recipients;
   exit the first-recipient change (`P1-P2`) and second-recipient payment (`P2`)
   in uniformly shuffled order. Six other notes remain private and immediately
   owner-exitable: two untouched credits, both first-sender changes, and the two
   corresponding notes from the non-target chain.
3. **`full-cashout`:** uniformly shuffle and execute owner-authorized full-note
   exits for all six remaining notes, confirm exact local payout fixtures and
   reach zero reserve/private liability.

No lock, delay, operator approval, batching, denomination padding, partial exit or
sacrificed recovery is introduced.

## Private workload commitment

Before wallet generation, sample and store in one `0600` file outside Git:

- both senders and recipient permutations;
- P1/P2 values;
- the valid four-transfer schedule;
- all four payment-output index bits;
- target chain;
- target-exit order and final six-exit order.

Publish only its size and SHA-256. The runner must validate the public policy and
commitment before generating keys. The observer uses this public policy but not
the exact private workload until predictions are sealed.

## Observer views

Apply four views over the same complete history:

- `O-public-known`: all public operation/state/checkpoint data plus every exit-
  destination owner mapping;
- `O-public-unmapped`: identical, without payout-owner mappings;
- `O-service-known`: O-public-known plus exact public-operation request bytes,
  sizes, receive order/times and neutral relay tokens;
- `O-service-unmapped`: O-public-unmapped plus the same service data.

All views receive:

- the complete chronological history, public domain/VK, commitments, nullifiers,
  anchors, ciphertext sizes/counts and operation kinds;
- deposit owners/amounts, exit values/destinations and payout fixtures;
- actual local monotonic ordering/timestamps and public checkpoint boundaries;
- this complete public policy and contact/identity restrictions.

Neutral local relay tokens have no admitted identity mapping and are not evidence
of real origin hiding. Packet/IP/global-network observations are unavailable.

## Frozen joint inference

Predictions consume all shared-ledger observations jointly and are hashed before
the scorer reads private workload/truth.

Enumerate only histories satisfying:

1. the four public credits and sender-group restrictions;
2. a one-to-one E/F first-recipient assignment and G/H second-recipient assignment;
3. one of the six public schedule mappings consistent with chronological transfer
   order and first-before-second dependencies;
4. public P1/P2 sampling bounds and positive conservation/change;
5. four unknown payment/change output partitions;
6. nullifier spentness and one historical input per transfer under the declared
   commitment/nullifier opacity assumption;
7. at `target-cashout`, a privately unknown target chain whose two public exits
   biject to that chain's `P1-P2` and `P2` roles in unknown order;
8. at `full-cashout`, a one-to-one mapping of every exit to all eight unspent note
   roles, satisfying both chains' conservation equations;
9. known payout identities only in `known` views; none in `unmapped` views.

Do not assume a visible withdrawal equals a particular earlier payment. Derive
payment amounts and relationships only through globally compatible histories.
Do not vary chain assignments independently when recipient permutations, schedule,
spentness or exit mappings couple them.

## Queries and metrics

At every checkpoint and for each chain/view report:

- first and second payment sender, recipient and relationship candidates;
- P1/P2 amount candidates or exact derived interval cardinality;
- historical funding/input commitment candidates;
- payment/change grouping candidates;
- compatible logical submitter identities, separately labeled from unmeasured
  network endpoint identity;
- joint two-chain topology count, schedule-mapping count and complete compatible
  history count;
- truth retention and unique truth identification.

The checkpoint passes only if every true queried item remains and every payment's
sender, recipient, relationship, amount, historical origin and grouping has at
least two candidates for all four views. Score all three checkpoints separately;
later failure does not erase earlier privacy.

Execution validity additionally requires genuine proof verification/application,
exact conservation, wrong-domain/root and replay rejection, backup-based received/
change recovery, owner-authorized exit for every note, diverted/unauthorized payout
rejection, exact payout fixtures and zero final reserve/liability.

## Baseline and controls

- Preserve the sparse predecessor manifest SHA-256
  `adb0da8835e82db929bcabf3d94ab7b189cb70df7b0f8eded4f41486138b0ce5`
  and compare its reported checkpoint counts without reinterpreting it as matched.
- The common-ledger workload differs in credit count, chain count, activity and
  schedule. It tests the combined shared-activity hypothesis; it cannot isolate
  which difference caused any change.
- Missing events/exits invalidate coverage.
- Renaming neutral relay tokens or public presentation order does not change
  candidate results.
- Removing payout-owner mappings weakly increases compatible histories; restoring
  them cannot increase histories.
- Removing either unrelated chain must change common-ledger candidates or make the
  frozen workload incomplete; isolated-chain counts cannot be silently summed.
- All true histories must remain compatible.

## Stop rules

- Do not retune values, identities, scheduling, exit order, observer data, attacks
  or thresholds after private workload commitment.
- Retain negative or mixed results without follow-up policy changes.
- Stop if the common ledger exceeds 16 leaves, any semantic rule beyond the
  accepted depth-four profile is required, proofs/accounting/recovery fail, truth
  reaches public/service artifacts, or joint scoring cannot be computed.
- No new primitive, capacity increase, batching/delay/denomination policy, MPC,
  prover/runtime/capture framework, paid compute, real funds, mainnet, funded
  Testnet/network action, commit or push.
