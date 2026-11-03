# Frozen user-chosen withdrawal with private-change experiment

**Freeze date:** 2026-11-01  
**Experiment identifier:** `wallet-local-private-change-v1`  
**Repository commit:** `7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1`  
**Capacity profile:** ADR-0018 depth four, 16 leaves, distinct local domain

This document freezes the finite experiment before exact workloads, wallet keys,
proofs or observations are generated. Values, arms, policies, observers, metrics,
thresholds and stop rules must not be retuned after commitment.

## Question

Does a user-chosen withdrawal implemented as:

```text
owned private note
-> ordinary private self-transfer(requested-withdrawal note, private-change note)
-> existing whole-note EXIT(requested-withdrawal note)
```

reduce linkage from public withdrawal amounts to earlier private payments? When
the owner later exits the private change, does the resulting public sum recreate
the original payment equation?

This is a two-operation wallet composition. The present EXIT does **not** support
atomic private change. The native payout amount and destination remain public.

## Distribution-matched arms

Run two alternative, independently sampled local ledgers under the same public
policy. They are experimental counterfactuals, not simultaneously observed users;
do not combine one arm's exact hidden realization with the other arm's public
history.

1. **`direct-exit-baseline`:** after two genuine private payment/re-spending
   chains, directly exit the target chain's full second-payment note and full
   first-recipient-change note.
2. **`private-change-candidate`:** self-split those same two role types into a
   requested-withdrawal note and recoverable private change; exit the requested
   notes, later exit both changes, then drain every other claim.

The arms are matched by public identity groups, amount distributions, topology,
operation classes, observer knowledge and final zero-liability requirement. Their
exact sampled senders, recipients, values, schedules and keys are independent so
publishing the baseline cannot disclose the candidate's private realization.

## Common arm policy

Use one ledger and eight independently keyed wallet contexts `A`–`H` per arm.
Credit fixed public deposit fixtures:

| identity | value |
|---|---:|
| A | 900,000,000 sompi |
| B | 800,000,000 sompi |
| C | 700,000,000 sompi |
| D | 600,000,000 sompi |

Create two unrelated chains:

- chain group 0 sender: uniform from `{A,B}`;
- chain group 1 sender: uniform from `{C,D}`;
- first recipients: a uniform one-to-one assignment of `{E,F}`;
- second recipients: a uniform one-to-one assignment of `{G,H}`;
- public contact edges: all `{A,B,C,D}->{E,F}` and `{E,F}->{G,H}` edges.

Sample integer-sompi payments:

| group | P1 | P2 |
|---|---:|---:|
| 0 | uniform `[220,000,000,500,000,000]` | uniform `[80,000,000,P1-80,000,000]` |
| 1 | uniform `[180,000,000,400,000,000]` | uniform `[60,000,000,P1-60,000,000]` |

Each chain executes `sender -> first recipient (P1)`, then restores the first
recipient backup and genuinely re-spends `P1 -> second recipient (P2)`. Each
transfer independently samples payment output index 0 or 1.

Uniformly sample one of the six valid interleavings of the two two-transfer
chains, preserving first-before-onward order. Uniformly choose one target chain.
The target role notes are its `secondPayment = P2` and
`firstRecipientChange = P1-P2` notes.

## Candidate requested-withdrawal policy

For each target role note of value `V`, owner-locally sample a synthetic user
request uniformly from:

```text
W in [10,000,000, V-10,000,000] integer sompi
R = V-W
```

`W` is the requested public withdrawal and `R` remains private and immediately
owner-exitable. Do not redraw collisions, round denominations or impose any
cross-role inequality.

Uniformly sample:

- the order of the two self-splits;
- the requested-note output index for each self-split;
- the order of the two requested exits;
- the order of the two remainder exits; and
- the final order of the six other exits.

The two self-transfers add four leaves to the common 12-leaf history, reaching the
existing capacity of 16 exactly. No new circuit, predicate, prover, runtime or
capacity profile is allowed.

## Checkpoints

Score each arm independently.

1. **`pre-withdrawal`:** after four credits and four genuine private transfers.
2. **`requested-withdrawal`:** baseline after direct full-note target exits;
   candidate after both self-splits and both requested-note exits, with both
   private changes and six other notes still owner-exitable.
3. **`remainder-withdrawal`:** candidate after both private changes exit. The
   baseline has no separate remainder and retains its requested-withdrawal state.
4. **`full-drainage`:** after every remaining note exits from an owner backup and
   exact offline payouts reduce reserve/private liability to zero.

No note is locked at any checkpoint. No delay, minimum residence time, batching,
denomination rule, operator approval or sacrificed recovery is introduced.

## Observer views

Apply four views to each arm's complete history:

- `O-public-known`: full public history plus exit-destination owner mappings;
- `O-public-unmapped`: same history without payout-owner mappings;
- `O-service-known`: known view plus exact public request bytes, order, size,
  local receive time and neutral relay tokens;
- `O-service-unmapped`: unmapped view plus that service evidence.

All public sampling policies, identity groups, contact edges, checkpoint
boundaries, operation kinds, exit amounts/destinations, state roots, commitments,
nullifiers, ciphertext sizes and chronological ordering are observer evidence.
Network/IP origin is unmeasured. Neutral relay tokens have no identity mapping.

Commitments, ciphertexts and nullifiers are treated as opaque except for public
equality, spentness and ordering. Do not infer a commitment link merely because
an amount equation is compatible.

## Frozen joint inference

Consume each arm's whole shared history jointly. Enumerate only histories that
satisfy:

1. sender groups, recipient permutations, contact edges and amount policies;
2. one of six original transfer schedules and all payment/change partitions;
3. target-chain selection without treating hidden chain labels as privacy;
4. baseline target exits as a bijection to `P2` and `P1-P2`;
5. candidate self-splits as a bijection to those target role notes, each obeying
   `V=W+R`, `W>=10,000,000`, `R>=10,000,000`;
6. known payout identities only in known views;
7. requested exits, later remainder exits and final exits as globally compatible
   one-to-one role assignments; and
8. conservation, public policy bounds and complete spentness.

The requested checkpoint must derive compatible earlier P1/P2 values from
inequalities, not assume a withdrawal equals a previous payment. The remainder
checkpoint must use public sums of requested and remainder exits where role
assignments permit them.

## Role-conditioned metrics

Use observable roles `withdrawing chain` and `unrelated chain`, never fixed hidden
chain indices. For every checkpoint, arm and view report candidate counts and
truth retention separately for:

- original funder and historical funding note;
- first and onward recipient/relationship;
- earlier received amount P1 and onward amount P2;
- requested and remainder exit-role assignment;
- historical onward input commitment;
- original and self-split payment/change grouping; and
- original transfer position, self-split position and public exit position.

Knowing a payment fact while its commitment or event position remains uncertain
is not full payment privacy. Do not collapse all properties into one anonymity
number.

## Decision thresholds

- Every true role-conditioned fact and coupled history must remain in its set.
- **Requested-withdrawal improvement:** candidate P1 and P2 counts must each be
  strictly greater than the baseline at the comparable checkpoint in both known
  and unmapped views. Report relationship/origin properties independently.
- **Remainder undo:** report whether candidate P1/P2, funder or relationship
  counts shrink when `R` exits; a unique fact is a privacy failure even if
  grouping or position remains ambiguous.
- **Full drainage:** score separately; later failure does not erase a measured
  requested-checkpoint improvement.
- Public and neutral-service projections must match for each identity view.

## Execution and regression controls

Require genuine proof verification/application, exact u64 conservation, backup
discovery of received notes and self-transfer outputs, owner-authorized exit for
every note, zero final reserve/liability and exact payout fixtures.

Retain wrong-domain, wrong-root, accepted-transfer replay, unauthorized discovery
and diverted-payout rejection. For the self-split path additionally test:

- requested amount below minimum, change below minimum and sum mismatch rejected
  before proof construction;
- replay rejected atomically;
- wrong owner cannot discover either split output; and
- restored owner discovers both requested and change outputs exactly once.

Regression controls must preserve:

- original shared-history manifest
  `1a9463269ef5647a1ce22b0af6b8e2121f236950fe2333873107c204f49677d9`;
- correction manifest
  `f11471b8fc290194dd461445c9a83dec511c78e5fd81bd8acd1a1acf4ca6700f`;
- known direct-exit target tuple uniqueness;
- unmapped direct-exit P1 uniqueness;
- hidden-label renaming invariance;
- payout-identity sensitivity;
- missing-event coverage failure; and
- complete coupled-truth retention.

## Stop rules

- Do not redraw, retune or add a second repair after commitment.
- Stop and retain the result if the self-transfer composition cannot be executed
  faithfully, exceeds 16 leaves, loses recovery, fails accounting/proofs, or the
  joint observer cannot retain truth.
- No MPC, new exit circuit, new prover/runtime, capacity increase, network or
  funded trial, real funds, mainnet, paid compute, commit or push.
- Keep workload, truth and backups outside Git. Publish public-safe evidence only.
- Stop after the measured comparison, whether positive, mixed or negative.

This experiment is distinct from failed H18 partial-cashout/short-delay policies:
it changes the public withdrawal amount through a private split, not the timing or
availability of the remaining claim.
