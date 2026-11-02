# Wallet-local practical-privacy experiment result

**Date:** 2026-11-01  
**Experiment:** `wallet-local-practical-privacy-v2`  
**Decision:** **privacy gate failed; wallet-local execution path passed.**

The measured wallet-local repairs removed the original source/publication and
deterministic-output leaks, but direct transparent exit still exposed the exact
payment amount in every trial. Known payout ownership also exposed the recipient
in one trial. No observed blocker requires MPC.

## Correction to the earlier result

The first `analyze.py` decoded real artifacts but inserted the expected candidate
counts and Alice/Bob/400,000,000-sompi assignment as constants. Those counts were
not a blinded measurement. `CORRECTION.md` preserves that fact.

The corrected baseline attack now derives candidates from the admitted published
source, operation bytes and exit fields. It recovered one candidate for sender,
recipient, amount, historical note, output partition and complete assignment.
The mandatory leaking-baseline control passed.

## What actually ran

- Three offline ledger trials, each with four fresh wallet keys, two genuine
  credits, one genuine transfer with randomized output order, recipient discovery,
  one genuine full-payment exit and an exact payout fixture.
- One fresh experimental Groth16 setup and 12 accepted proofs: six credits, three
  transfers and three exits.
- All accepted transfers rejected replay atomically; diverted payouts rejected;
  recipients recovered payments; senders recovered change; the other depositor's
  note remained recoverable; final private liability equalled reserve.
- The run took 68.454 seconds. Setup took 8.511 seconds; the 12 proofs took 59.419
  seconds in total (4.921–5.117 seconds each) with four Rayon threads.
- A separate capture process received each of the 12 exact public operation
  requests. It received public operation data plus a fresh neutral relay token,
  not a wallet, key, note, witness, role or authenticated identity.

No network, Testnet, funding, MPC, paid compute or original-service recovery ran.

## Measured observer result

Predictions were serialized and hashed before the scorer read private truth.
Every true item remained in its candidate set; the attack did not win by dropping
truth.

| Hidden item | O-public candidates by trial | O-service candidates by trial | Unique truth identifications |
|---|---:|---:|---:|
| sender | 2 / 2 / 2 | 2 / 2 / 2 | 0 / 3 |
| recipient | 1 / 2 / 2 | 1 / 2 / 2 | 1 / 3 |
| payment amount | 1 / 1 / 1 | 1 / 1 / 1 | 3 / 3 |
| historical input note | 2 / 2 / 2 | 2 / 2 / 2 | 0 / 3 |
| payment/change partition | 2 / 2 / 2 | 2 / 2 / 2 | 0 / 3 |
| complete assignment | 4 / 8 / 8 | 4 / 8 / 8 | 0 / 3 |

Public and service results are identical because the measured service boundary was
public-only and its relay tokens carried no identity mapping. This is evidence
about that process interface, not network anonymity.

## What improved versus the leaking baseline

- role-neutral runtime artifacts prevented direct source/filename truth recovery;
- two genuine credited notes left two sender and historical-note candidates in
  every trial;
- randomized output order left both payment/change partitions compatible;
- neutral service requests added no sender information beyond the public view;
- complete assignments rose from one in the baseline to four or eight.

These are bounded executable results. The declared commitment, ciphertext,
nullifier and zero-knowledge opacity assumptions were not cryptographically
re-proved by this run.

## Exact remaining leaks

1. **Amount:** each recipient immediately exited the full payment. The frozen
   direct-exit attack therefore predicted the public exit principal and uniquely
   recovered the true payment amount in all three trials.
2. **Recipient:** the simulated legitimate auxiliary mapping for `trial-00` said
   its public exit destination belonged to C. That reduced recipient candidates
   from two to one and recovered the true recipient. Removing that observation in
   the frozen control restored two candidates.
3. **Small history:** the existing depth-two append-only circuit permits only two
   prior credits before a two-output transfer fills the tree. This run cannot
   establish large-pool anonymity.
4. **Evidence boundary:** keys were independently generated but all contexts ran
   on one host. This is not independent custody or administration. Packet/global
   network privacy, live native consensus, funded payout and off-operator recovery
   remain unavailable evidence.

## Smallest next hypothesis

The observed failure is public exit layout and linkage, not private witness
processing. Continued private spending or a separately frozen shared exit-batch
experiment could test whether payment amount and known payout identity remain
linkable. Prior short-delay/partial-cashout work failed, so neither delay nor
batching is claimed as a fix here.

Joint/private computation is not justified by this result: the processor learned
no private map, while MPC could not hide a distinctive public exit amount or a
known payout owner.

## Reproducible artifacts

- frozen v1 selection: `EXPERIMENT-SELECTION.md`
- pre-execution v2 correction: `EXPERIMENT-SELECTION-V2.md`
- runner and public-boundary capture: `runner/`, `service_capture.py`
- observer, scorer and controls: `observer.py`, `score.py`, `controls.py`
- public-safe receipts: `run-v2/public/`
- sealed prediction canonical SHA-256:
  `7bc80570c20eae7e5df2d2d662839e4f0dcdcb3f3a678f68b532e24ebf65418d`

All four scorer controls passed: corrected leaking baseline recovery, irrelevant
relay-alias/order invariance, exit-identity evidence sensitivity, and missing-credit
candidate/coverage sensitivity. The public-safety audit found 12 owner-local
backups, no backup encoding in public files, 12 exact capture/event pairs and no
published private truth values.
