# Frozen continued-private-spending experiment

**Freeze date:** 2026-11-01
**Experiment identifier:** `wallet-local-private-spend-v1`
**Repository commit:** `7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1`
**Predecessor retained unchanged:** `research/wallet-local-payment-privacy-2026-11-01/run-v2/public/`

This selection is frozen before creation of fresh wallets, hidden assignments,
operation bytes, observations or predictions. Its SHA-256 is recorded before
execution. Values, assignment rules, observers, attacks, thresholds and stop
rules must not be retuned after truth or observations exist.

## Question

Does a recipient spending a received note privately again preserve ambiguity
about the first and second payment relationships and amounts, and how much of
that ambiguity survives after every remaining claim is eventually withdrawn?

The matched control replaces the second private transfer with an immediate
full-payment exit. The experiment compares executed paths; it does not claim the
branches have identical public operation shapes after their deliberate divergence.

## Existing-path and capacity decision

The repository has no compatible larger-capacity wallet-local path. Wallet,
private-state, native, recovery and TN10 packages all import the same
`poc/private-note-wallet` depth-two tree. Two credits plus one two-output transfer
fill its four leaves, so it cannot execute a second private transfer.

Add one experiment-only Cargo feature to the existing wallet crate:

- tree depth `4`, capacity `16`;
- domain exactly
  `SHA256("KPI/LOCAL-NO-FUNDING/native-KAS/private-note-experiment-depth4-v1")`;
- fresh one-party experimental Groth16 parameters and verifier identity;
- unchanged note commitment, owner, nullifier, encryption, authorization,
  conservation, anchor, replay and exit semantics;
- default builds remain depth two with their original domain and evidence.

The feature must reject combination with `tn10-rehearsal`. This is a bounded local
profile, not a production parameter choice or migration of retained state.

## Fixed matched workload

Run two matched pairs. Each arm has six fresh wallet contexts `A`–`F` and two
authenticated offline deposit fixtures:

| pair | A deposit | B deposit | first payment P1 | onward payment P2 |
|---|---:|---:|---:|---:|
| `pair-00` | 900,000,000 | 700,000,000 | 300,000,000 | 180,000,000 sompi |
| `pair-01` | 850,000,000 | 650,000,000 | 250,000,000 | 140,000,000 sompi |

Choose `pair-00`'s hidden chain with three unbiased OS-random bits:

- first sender `S1` from `{A,B}`;
- first recipient/onward sender `R1` from `{C,D}`;
- second recipient `R2` from `{E,F}`.

`pair-01` uses the opposite member of each set. Both arms in a pair use the same
identity chain and values but fresh independent keys, notes, proofs and output
ordering. No choice depends on observer predictions.

### Continued-private arm

1. credit A and B with genuine proofs;
2. `S1` privately pays P1 to `R1` and receives positive change;
3. restore `R1` from its owner-local backup, discover P1 from accepted public
   records, privately pay P2 to `R2`, and receive positive change;
4. checkpoint `pre-cashout` before any exit;
5. randomize the order of the four remaining owner-authorized full-note exits:
   untouched depositor, first sender change, first recipient change and P2;
6. confirm exact offline payout fixtures and reach zero reserve/liability.

### Immediate-exit control arm

1. credit A and B with genuine proofs;
2. `S1` privately pays P1 to `R1` and receives positive change;
3. restore `R1`, discover P1, immediately exit it in full and confirm its exact
   offline payout fixture;
4. checkpoint `pre-cashout` after that deliberate public exit;
5. randomize the order of the two remaining owner-authorized full-note exits:
   untouched depositor and first sender change;
6. confirm exact offline payout fixtures and reach zero reserve/liability.

Every transfer independently randomizes payment/change output order before proof
construction. Every exit is prepared from a restored wallet backup and accepted
public state. No residence time, operator approval, minimum delay or lock is added.

## Observer views

### O-public

- exact serialized operations, public statements, commitments, ciphertext
  lengths/counts, anchors, nullifiers and verifier/domain;
- authenticated fixture deposit owner hashes and amounts;
- operation order and actual local monotonic timestamps;
- every public exit amount/destination and payout fixture;
- public arm/pair labels and checkpoint boundaries;
- simulated auxiliary knowledge below.

### O-service

O-public plus the exact request bytes, sizes, receipt order/times and fresh neutral
relay token received by a separate capture process. The token has no admitted
identity mapping. This is an actual same-host software boundary, not real network
origin hiding.

### Simulated legitimate auxiliary knowledge

- identity universe `{A,B,C,D,E,F}` per arm;
- both transparent deposit-owner mappings to A and B;
- contact graph `{A-C,A-D,B-C,B-D,C-E,C-F,D-E,D-F}`;
- for both arms in `pair-00`, every exit-destination identity is known;
- for both arms in `pair-01`, no exit-destination identity is known;
- no endpoint/relay token is mapped to an identity.

### Declared assumptions and unavailable evidence

Commitment hiding, ciphertext/key privacy, nullifier unlinkability, zero knowledge
and proof soundness remain assumptions. Genuine proof execution is not a general
cryptographic proof. Packet/global-network observations, independent
administration, physical off-host custody, live consensus, funded payout and
service-shutdown recovery are unavailable.

## Frozen joint attacks

Predictions consume only admitted observations and auxiliary data. They are sealed
and hashed before a separate scorer reads owner-local truth.

### Structural rules

- credit outputs have their public credited values and deposit-owner identities;
- every transfer has one positive input and exactly two positive outputs whose
  values sum to the input; payment/change output order is unknown unless evidence
  determines it;
- a nullifier does not reveal its historical commitment under the declared
  assumption;
- exits reveal value/destination but are assigned jointly to compatible unspent
  notes; the attack must not assume an exit equals the immediately preceding
  hidden payment except in the public immediate-exit control branch;
- assignments must satisfy the full multi-payment conservation history, contact
  graph, known payout identities, operation sequence and one-to-one exit mapping.

### `pre-cashout` checkpoint

For the continued arm, enumerate jointly:

- `S1` from compatible credited owners and its historical credit;
- `R1` from `S1`'s C/D contacts;
- `R2` from `R1`'s E/F contacts;
- P1 over every positive integer leaving positive first change for a compatible
  input value, represented as derived intervals/counts rather than materializing
  hidden workload lists;
- P2 over every positive integer strictly below candidate P1;
- both output partitions for each transfer;
- endpoint identities compatible with the corresponding sender candidates.

For the control arm, use the public immediate exit to constrain P1 and, when
admitted, its owner identity. Do not import the hidden assignment.

### `post-cashout` checkpoint

Jointly enumerate candidate chains and bijections from all public exits to all
remaining note roles. For the continued arm, a valid assignment must satisfy:

```text
untouched credit = other depositor value
first change     = selected input value - P1
second payment   = P2
second change    = P1 - P2
```

For the control arm, the immediate exit fixes candidate P1 and the later exits
must match untouched credit and first change. Apply known payout identities only
where frozen auxiliary evidence supplies them. Exit order alone carries no fixed
role rule because the controller randomizes it.

## Queries and metrics

For each arm, observer and checkpoint report:

- first payment: sender, recipient, amount, historical credit and output grouping;
- continued arm second payment: sender, recipient, amount, historical first-
  transfer output and output grouping;
- joint relationship chain and complete structural assignment counts;
- compatible endpoint identities for each transfer;
- truth retention and unique truth identification for every query;
- exact minimum/median/maximum candidate counts or derived interval cardinality.

The continued-private checkpoint passes the bounded gate only if every true item
is retained and every relationship, amount, historical origin, grouping and
endpoint identity has at least two candidates for both observers. The post-
cashout checkpoint is scored separately with the same threshold; later failure
does not erase a pre-cashout pass.

Execution validity additionally requires all proofs verify/apply, exact value
conservation, atomic replay/wrong-domain/wrong-root rejection, backup-based
received/change discovery, independently authorized exits for every remaining
note, exact payouts and zero final reserve/liability.

## Mandatory controls

1. v2's immediate-exit result remains unchanged and is the external baseline.
2. Every observation has an exact service capture and acceptance receipt; missing
   required operations or exits invalidate coverage.
3. Irrelevant relay-token and presentation-order renaming does not change scores.
4. Removing `pair-00` payout-identity mappings weakly increases relationship/exit
   assignment candidates; restoring them cannot increase candidates.
5. Removing or changing an exit changes feasible assignments or invalidates full-
   cashout coverage; it cannot silently preserve a pass.
6. Predictions are sealed before truth access and all true assignments must remain
   candidates.

## Stop rules

- Do not retune values, assignments, output/exit order, timing, observer data,
  attacks or thresholds after fresh truth/observations exist.
- Retain honest failure; new hypotheses require a separately frozen follow-up.
- Stop if the capacity profile changes any semantic rule beyond depth/domain, a
  proof/invariant/recovery check fails, truth reaches public/service artifacts, or
  joint scoring cannot be computed from observations.
- Implementation defect fixes must preserve this freeze and be recorded.
- No MPC, paused-checkout edit, mainnet, real funds, funded network/Testnet trial,
  paid compute, new prover/runtime subsystem, commit or push.
