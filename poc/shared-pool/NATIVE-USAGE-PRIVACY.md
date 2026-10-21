# Native usage privacy screen

Status: completed with observed finite-case cap warnings, 2026-10-21
(Australia/Sydney). The privacy gate remains open.

The preceding stronger screen was committed and pushed as
`9ae5b3efeb1698cf45d35e064c95f91c1ac5a54e`. This follow-up tests one fresh
32-wallet/eight-colluder history with 64 ordinary payments, uneven activity,
repeat contacts, receipt spending, intermediate cashouts and four native
self/cross-user funding bridges. See [RFC-0015](../../docs/rfc/0015-native-usage-privacy-screen.md)
and the [prospective specification](NATIVE-USAGE-PRIVACY-SPEC.md).

## Frozen experiment

- Frozen at 2026-10-21 01:21:18 UTC; private seed sampled at 01:21:42 UTC.
- Freeze SHA-256: `f841e1d66a1f3e5fdd564aefe035701e3a32c41ffe0f7d4ca498d94509e74ac5`.
- Seed-file commitment: `aa77ea3e52e3a466cd1de83b29d7f890725b410a67b271c5ff84137a1853bfab`.
- Frozen code, binaries, parameter identity, policy and dependency files precede
  fresh wallets, proofs and evaluation. All predictions were sealed before
  private scoring.
- All 109 isolated development control groups passed. Separate native-context
  rejection tests, published native replay and a public full-size concrete-truth
  solver check passed. These are implementation checks, not a cryptographic audit.

The four fixed attacks are a policy-aware prior, residual-value guesses,
split-value guesses and native graph guesses. Ten observer profiles see only
their permitted public prefix and participant records. The three horizons are
payment creation, the next public DRAIN and final drainage: 1,920 target/profile/
horizon combinations. Strict cap comparisons use exact fractions.

## Completed result

Generation finished at 04:05:40 UTC; all 830 profile/prefix predictions were
sealed at 04:12:30 UTC; scoring completed at 04:13:25 UTC (15:13 Sydney).
All 83 prefixes, ten observer profiles and 1,920 target/profile/horizon
combinations completed. The completed result is
`observed-finite-case-cap-warning`, with `qualification_pass: false`.

There were 64 ordinary payments, including **36 honest-to-honest primary
payments**. The table reports correct guesses within 10% of the amount; each
denominator is those same 36 payments. C+D sees public bytes plus the declared
initial funding-owner directory. Pooled adds all eight colluders' permitted
records. These are dependent views of one history, not independent samples.

| Observer and horizon | Prior only | Strongest frozen amount attack | Improvement |
| --- | --- | --- | --- |
| C+D, payment creation | 7/36 (19.44%) | 7/36 (19.44%) | 0 pp |
| C+D, next public withdrawal | 7/36 (19.44%) | 12/36 (33.33%) | 13.89 pp |
| C+D, final drainage | 7/36 (19.44%) | 10/36 (27.78%) | 8.33 pp |
| Pooled, payment creation | 7/36 (19.44%) | 7/36 (19.44%) | 0 pp |
| Pooled, next public withdrawal | 7/36 (19.44%) | 10/36 (27.78%) | 8.33 pp |
| Pooled, final drainage | 7/36 (19.44%) | 10/36 (27.78%) | 8.33 pp |

Residual/native-graph guesses tie at the next-withdrawal horizon. All three
transaction-based variants tie on final within-10% accuracy. The next public
withdrawal is chosen from the public sequence, **not** by knowing the target
recipient's private cashout. Exact amount hits at that horizon are 6/36 for
C+D and pooled residual/native-graph guesses; final split/native-graph hits are
5/36. Correct guesses are not proven unique disclosures.

The measured amount rates exceed the frozen 20% absolute cap and five-percentage-
point improvement cap. The observed prior alone is 19.44%, below the absolute
cap, so this result cannot be explained solely by the pre-run prior warning.
There are 95 amount comparison warnings and one sender comparison warning,
with substantial repetition across views, variants and horizons. P1's final
split guess identifies 2/36 senders against prior 0/36: +5.56 pp, just over the
five-point improvement cap and below the 10% absolute sender cap.

Across every frozen profile, variant and horizon, no primary joint sender–
recipient guess is correct (0/36). This does not establish relationship privacy
or rule out stronger attacks. No exhaustive forced-disclosure search was run.

All four transparent bridge edges are visible. Every profile makes two
same-owner guesses: one correct and one cross-user false positive, with two
abstentions on fresh unassociated funding scripts. Native value flow therefore
does not justify a common-owner assertion. These four adversarial-payment
controls are not a broad graph-resistance test.

## Native execution and verification

The history contains 159 genuine proof-bearing operations: 35 admissions,
64 ordinary PAYs plus one founding self-payment, and 59 withdrawals. There are
196 native transactions including funding parents and four ordinary bridges.
Payments used one input 49 times and two inputs 15 times; 13 spent earlier
payment receipts and two spent re-admission credits. Every claim drained;
the final pool reserve is zero. Original wallet backups remained unchanged.

Native signature/proof validation and separate full-history replay passed.
The whole-experiment reconciliation, including external change and recycled
coins, is exact in integer sompi:

```text
2,594,580,000,000 external injection
= 2,588,182,611,800 final native unspent value
+     6,360,000,000 pool fees
+        37,388,200 ordinary transaction fees
```

Both original algebraic encodings accept the concrete final witness (CP-SAT
and Z3 SAT). This checks the generated witness, not uniqueness or cryptographic
soundness. The completed 109 pre-run controls and additional native checks
remain implementation evidence.

A separate [post-run arithmetic recount](artifacts/native-usage-privacy-20261021-recount.json)
agrees with every score: zero discrepancies across 228 comparison groups,
covering all 1,920 selections, 2,400 metric counters, 1,440 ranked counters,
270 paired advantages, known-fact exclusions and bridge confusion counts.
Its independent arithmetic does not import the frozen scorer or observers;
it reuses the reviewed public verifier before reading the hash-bound hidden truth.
Twenty public controls and a separate source/guard review passed. This recount
is outside the frozen experiment and adds no attack or privacy qualification.

## Retained evidence and decision

The [public evidence](evidence/2026-10-21-native-usage/README.md) retains exact
native bytes, frozen source/specification, permitted participant views, sealed
predictions, aggregate scores and process/identity receipts. Post-run export
verifies source hashes, prefix cuts and the all-predictions-before-score barrier.
Its manifest lists exact originals and explicit path-redacted derivatives;
`SHA256SUMS` binds the package. Combined predictions are reversibly gzip-packed;
the manifest preserves both compressed and original byte hashes. All 31
post-run exporter controls pass. Seeds, backups, full truth, honest scans and
private operational logs remain outside Git.

Keep this result unchanged. Investigate why public withdrawals improve amount
guesses and compare mitigations before dedicated milestone 3 work. Any follow-up
analysis on this now-seen history is exploratory; a mitigation needs a new
prospectively frozen test. Do not weaken the privacy caps, restrict independent
exit or describe this completed screen as a privacy pass.

## Pre-run warning

The honest payment-size distribution makes the fixed 45-tKAS prior correct within
10% with probability `21103/100025`, about 21.10%. That already exceeds the
unchanged 20% absolute amount target in expectation, without transaction leakage.
The result must distinguish this usage predictability from any added advantage
provided by native transaction data. No target was relaxed.

## Evidence limits

Transactions, signatures, proofs and ciphertexts are genuine, locally validated
wallet output. Initial funding ancestry and accepted heads are synthetic offline
fixtures. Modeled request times are not chain or network measurements. Generation
uses one trusted process holding fresh fixture wallets; observers are isolated.
No funds, broadcasts or new setup are involved.

One dependent history is a native case study, not representative human usage or
statistical qualification. Graph value flow does not prove common ownership.
Correct heuristic guesses do not establish forced disclosure. Every outcome
leaves the privacy gate open and `qualification_pass` false.
