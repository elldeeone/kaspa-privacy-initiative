# Continued private spending and eventual exits — measured result

**Date:** 2026-11-01  
**Experiment:** `wallet-local-private-spend-v2`  
**Decision:** **continued private spending passed before cashout; eventual exits
partly or fully undid that privacy. No observed result requires MPC.**

## What actually ran

- Two matched pairs, each with a continued-private arm and immediate-full-exit
  control; 24 fresh owner-local wallet backups in total.
- The continued arms executed `S1 -> R1 -> R2` with genuine received-note
  discovery and re-spending from restored backups before any exit.
- One fresh depth-four/domain-separated Groth16 setup and 28 accepted proofs:
  eight credits, four first transfers, two onward transfers, two immediate exits
  and twelve eventual exits.
- Every remaining note was exited by its restored owner wallet. Exact local payout
  fixtures reduced final reserve and private liability to zero in all four arms.
- Wrong-domain, wrong-root, accepted-transfer replay and diverted-payout variants
  rejected atomically. The unchanged default depth-two suite passed all nine tests.
- Execution took 163.980 seconds with four Rayon threads. Setup took 9.839 seconds;
  the 28 proofs took 152.970 seconds total (5.426–5.751 seconds each).

No network, Testnet, real funds, paid compute, MPC or outer prover ran.

## Sealed observer result

Predictions used the complete joint public history and were hashed before the
scorer read the committed private workload or truth. Every true item remained in
its candidate set.

### Before eventual cashout

Both continued-private arms passed for O-public and O-service:

| Query | Pair 00 candidates | Pair 01 candidates |
|---|---:|---:|
| first sender / recipient | 2 / 2 | 2 / 2 |
| first amount | 899,999,998 | 849,999,998 |
| first funding note / output grouping | 2 / 2 | 2 / 2 |
| second sender / recipient | 2 / 2 | 2 / 2 |
| second amount | 899,999,998 | 849,999,998 |
| second historical output / grouping | 2 / 2 | 2 / 2 |
| joint relationship chains | 8 | 8 |

The large amount cardinalities follow the admitted protocol-only observer model:
positive integer sompi outputs and conservation, without a disclosed wallet
denomination policy. They are not a production anonymity estimate.

The immediate-exit controls exposed P1 exactly at the same checkpoint: one amount
candidate in both pairs. Pair 00's admitted payout-owner mapping also exposed R1;
pair 01 retained two possible recipients. Thus actual continued private spending
materially improved payment-amount and relationship ambiguity versus the executed
immediate-exit branch.

### After every eventual withdrawal

The continued-private post-cashout gate failed.

- **Pair 00, known payout owners:** joint arithmetic plus identity mappings left
  one `S1 -> R1 -> R2` chain, one P1, one P2, one first funding note and one
  relationship for each payment. Only both transfer output groupings and the
  second historical output retained two candidates. Complete structural
  assignments fell to four.
- **Pair 01, unknown payout owners:** later exit arithmetic still identified S1
  and its historical credit, but retained three P1 values, three P2 values, two
  R1 candidates, two R2 candidates and four relationship chains. Transfer
  groupings and the second historical output retained two candidates. Complete
  structural assignments fell to 96.

Removing pair 00's payout-identity mappings in the frozen control increased its
post-cashout relationship chains from one to four and complete assignments from
four to 96. This isolates the material effect of legitimate identity knowledge;
the result is not attributed to decryption.

## Public versus processing service

O-public and O-service scores were identical. The separate service process
received exactly the public operation plus a fresh neutral relay token; it did
not receive notes, values, keys, witnesses or role labels.

This does **not** demonstrate real origin hiding. The reported endpoint candidates
are identities compatible with the logical sender under the frozen sender-submits
assumption. No packet, IP, authenticated endpoint or global-network observation
was available, and the neutral local token supplied no empirical anonymity fact.

## What this means

1. Receiving and spending privately again protected both payment amounts and
   relationships at the measured pre-cashout checkpoint.
2. Transparent withdrawals can retroactively collapse that protection through
   exact conservation and payout-identity knowledge—even when no ciphertext or
   nullifier link is broken.
3. Unknown payout ownership preserved more ambiguity, but full cashout still
   exposed the first funding sender in the sparse two-credit history.
4. Output grouping remained ambiguous because the observer could not link exit
   nullifiers to commitments under the declared cryptographic assumption.
5. No observed blocker requires joint MPC. MPC would not hide public exit values,
   conservation equations or externally known payout owners. The next unresolved
   issue is public exit-set structure and a genuinely larger activity set, not
   private witness processing.

No delay, batching, denomination or partial-cashout policy is claimed as a fix.
The prior H18 negative result remains intact.

## Evidence limits

- Depth four is an experiment-only Cargo feature with a distinct domain and fresh
  parameters. Default depth two and retained evidence remain unchanged.
- Same-host independently keyed contexts are not independently administered users
  or off-operator recovery.
- Deposits/exits/payouts are authenticated offline fixtures, not native consensus.
- Commitment, encryption, nullifier and zero-knowledge opacity are assumptions,
  not properties re-proved by this run.
- Pair 00 identity mappings and all contact knowledge are explicitly simulated
  auxiliary evidence.

## Reproducible artifacts

- frozen design and correction: `SELECTION.md`, `SELECTION-V2.md`
- pre-wallet workload commitment: `WORKLOAD-COMMITMENT.json`
- architecture decision: `docs/adr/0018-depth-four-private-spend-experiment.md`
- genuine runner: `runner/`
- joint observer/scorer: `observer.py`, `score.py`
- public receipts and sealed score: `run-v2/public/`
- sealed prediction canonical SHA-256:
  `067f7c10a1d39dbbb5c8f9b79c398b1e4abc0ed61832602256535f1b45be0ae7`

All observer controls and the public-safety audit passed. The audit found 28 exact
capture/event pairs, 24 owner-local backups, no backup encoding in public files,
no copied private workload file and no published private truth values.
