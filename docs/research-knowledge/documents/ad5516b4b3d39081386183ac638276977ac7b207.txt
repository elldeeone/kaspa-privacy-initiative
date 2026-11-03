# Frozen wallet-local practical-privacy experiment

**Freeze date:** 2026-11-01
**Repository:** `/home/luke/projects/kaspa-privacy-initiative`
**Source commit:** `7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1`
**Status at freeze:** protocol and scoring plan frozen before creation of fresh
wallets, hidden assignments, operation bytes or observations.

This file becomes immutable once its SHA-256 is recorded. Implementation may
correct code defects needed to execute this design, but may not change the
workload, denominations, assignment rule, observers, attacks, thresholds or stop
rules after fresh truth or observations exist. Any substantive change requires a
new experiment identifier and a new freeze.

## Question

After the smallest wallet-local repairs—generic private runtime inputs,
role-neutral public artifacts and randomized payment/change output order—what can
a public observer and a public-only processing service infer about sender,
recipient, payment amount, historical input note and payment/change grouping?

This run tests the existing local four-leaf note circuit and ledger. It does not
claim a large shared pool, network anonymity, independent administration,
production security or cryptographic proof of opacity.

## Fixed workload

Run exactly three trials with one shared freshly generated Groth16 parameter set.
Each trial uses four fresh, independently keyed wallet contexts named only in
private truth as `A`, `B`, `C`, and `D`:

| trial | A deposit | B deposit | payment |
|---|---:|---:|---:|
| `trial-00` | 900,000,000 | 700,000,000 | 300,000,000 sompi |
| `trial-01` | 850,000,000 | 650,000,000 | 250,000,000 sompi |
| `trial-02` | 1,000,000,000 | 800,000,000 | 350,000,000 sompi |

For every trial:

1. register authenticated offline deposit fixtures for A and B;
2. make and accept one genuine credit proof for each deposit;
3. choose one sender from `{A,B}` and one recipient from `{C,D}`;
4. make and accept one genuine whole-note transfer, with payment fixed by the
   table and positive change returned to the sender;
5. choose payment/change output order with a fresh unbiased random bit before
   proof construction;
6. have the selected recipient discover the note from accepted public records,
   make and accept a genuine full-payment exit proof, and confirm the exact
   offline payout fixture;
7. retain replay, wrong-root or payout-diversion rejection checks without
   weakening any existing predicate.

Shuffle the four possible `(sender, recipient)` pairs with OS randomness and use
the first three without replacement. This guarantees more than one actual
relationship without choosing assignments after seeing observer predictions.
All keys, note plaintexts, assignments, output roles and wallet backups stay in
an owner-local directory outside the repository with directory mode `0700` and
secret files mode `0600`.

The circuit's append-only depth is two. Two credits plus two transfer outputs fill
the tree; the run must not simulate or claim a larger same-ledger anonymity set.

## Repairs under test

Only these repairs are admitted:

- wallet roles and values enter as private runtime state rather than public source
  constants;
- public files, trial identifiers and service requests are role-neutral;
- payment/change output order is independently randomized per trial;
- the processing boundary receives serialized public operations plus a neutral,
  per-request relay token, never a wallet object, key, note, witness, assignment
  or role label.

No delay, denomination padding, partial cashout, batching, dummy user, altered
cryptography, extra tree capacity or MPC is admitted as a repair in this run.

## Observations and evidence classes

### Actual public observations

- serialized credit, transfer and exit operation bytes;
- public statement fields, commitment and ciphertext counts/sizes;
- accepted state roots, operation order and actual local monotonic timestamps;
- public deposit fixture identifiers, owners and amounts;
- public exit destination and amount;
- exact payout-fixture amount/destination and proof/application receipts.

### Actual processing-service observations

- the exact public operation request received by a separate capture process;
- request size, order, monotonic receipt time and a fresh neutral relay token;
- no wallet role, stable endpoint identity or private witness.

The separate process is an actual software interface boundary, not adversarial
same-host isolation.

### Simulated auxiliary knowledge

- identity universe `{A,B,C,D}` per trial;
- public mappings from the two transparent deposit owners to A and B;
- contact graph `{A-C, A-D, B-C, B-D}`;
- for `trial-00` only, the public knows the exit destination belongs to C;
- neutral relay tokens are assumed not mapped to an identity.

### Declared cryptographic assumptions

Commitment hiding, ciphertext/key privacy, nullifier unlinkability, zero knowledge
and proof soundness are assumptions for observer enumeration. Genuine proofs and
verification test the executable path, not those general cryptographic claims.

### Unavailable evidence

Packet/global-network observations, independently administered wallets, off-host
custody, live Testnet consensus, funded payouts, service shutdown recovery and a
pool larger than two prior notes per trial.

## Frozen attacks and enumeration

Predictions consume only public/service observations and the declared auxiliary
file. They must not read private truth or source-specific role constants.

For each trial:

1. `historical-note`: enumerate every unspent credited note present before the
   transfer whose public credited value is strictly greater than the later public
   exit amount. Bind each note to its auxiliary deposit-owner identity.
2. `sender`: the owners of compatible historical notes. For the service observer,
   intersect only with an authenticated endpoint identity if such an admitted
   field exists; a neutral relay token does not intersect identities.
3. `recipient`: enumerate contact-graph neighbors of compatible senders in
   `{C,D}`. If an admitted exit-destination identity mapping exists, intersect
   with it.
4. `amount`: the direct-exit attack predicts the public exit principal as the
   payment amount. No other amount is added merely to improve ambiguity.
5. `grouping`: enumerate both transfer-output partitions unless an admitted
   observation explicitly labels a payment or change output.
6. `complete assignment`: enumerate all tuples consistent with the note-owner,
   contact, amount and partition constraints.

Predictions are serialized and hashed before a separate scorer is given the
private truth. Candidate counts, truth retention and unique truth identification
are computed, not entered as expected results.

## Metrics and thresholds

Report per observer and trial:

- candidate counts for sender, recipient, amount, historical note, output
  partition and complete assignments;
- whether each true item remains in its candidate set;
- whether each true item and complete assignment are uniquely identified;
- aggregate minimum/median/maximum candidate counts.

The repaired route passes this bounded privacy gate only if, for **every** trial
and both observers:

- all true items are retained;
- sender, recipient, amount, historical note and output partition each have at
  least two candidates;
- at least two complete assignments remain;
- all genuine proofs verify and apply, value conservation holds, the recipient
  recovers the payment, exact payout succeeds, and replay/diversion controls
  reject.

Any unique hidden item is a gate failure. Missing truth is an attack/scorer
failure, not privacy. Missing required observation or proof receipt invalidates
the run.

## Mandatory controls

1. The original published 10/4/6 baseline must be reconstructed from admitted
   files and yield the known unique assignment without hard-coded candidate sets.
2. Renaming irrelevant public aliases and reversing trial presentation order must
   leave candidate counts and truth scores unchanged.
3. Removing `trial-00`'s admitted exit-identity mapping must increase its recipient
   candidates; restoring it must reduce them.
4. Removing one admitted pre-transfer credit must reduce historical-note and
   sender candidates, and the completeness check must flag the missing required
   observation rather than silently score a pass.
5. Every public operation sent to the scorer must have a matching capture and
   acceptance receipt; no required observation may be silently dropped.

## Stop rules

- Do not retune values, relationship assignments, timings, attack logic,
  thresholds or randomization after truth/observation generation.
- Retain an honest privacy failure if proofs and scoring are valid.
- Stop and report precisely if the existing circuit cannot execute the workload,
  a required proof/application invariant fails, truth leaks into public/service
  artifacts, or sealed scoring cannot be established.
- Fix only implementation defects that preserve this frozen design; record every
  such correction.
- No MPC work, paused-checkout edits, network/funded trial, paid compute, prover
  rewrite, mainnet action, commit or push.
