# Equal net deposits: H12

The frozen offline comparison passes: making all four private credits equal
after admission fees prevents unique deposit reconstruction by the tested
joint-history attack, including after complete drainage. This is a candidate
wallet funding policy, not a privacy certification. Genuine native calibration,
a complete TN10 rehearsal and a fresh measured trial passed. Every wallet exited
independently using its already prepared proof, with no remaining reserve.

## What changed and what did not

[Specification](NORMALIZED-DEPOSITS-SPEC.md), frozen at `a522e59` before
generation; baseline `5cfa94d`. The three policies have the same total backing,
fees, transfer topology, ownership, exit order and schedule within each paired
ledger. Contributions are varied, equal before fees, or equal after fees.
All exits use fresh proofs; creation-root proofs stay private as fallbacks.
The circuit, parameters, covenant, fees and full-withdrawal relation are unchanged.

Bootstrap costs 21,893,200 sompi; each later admission costs 22,005,200.
Equal gross contributions therefore leave a 112,000-sompi difference between
the first and later private credits. H12 removes that difference by changing
how much each wallet funds, while preserving the pool's total funding. This is
a wallet policy; the covenant still permits other valid amounts.

## Offline inference results

64 paired four-wallet ledgers: 32 sparse and 32 burst, with 704 withdrawal
targets **per policy**. There are two additional no-cover controls, not extra
independent samples. Every draw is retained. These are new workloads; do not
combine their percentages with H11's different sampling/matching scheme.

| Funding policy | Unique deposit, sparse | Unique deposit, burst | Strongest fixed deposit guess, sparse / burst |
| --- | ---: | ---: | ---: |
| Varied | 91.875% (294/320) | 84.115% (323/384) | 96.563% / 91.927% |
| Equal gross | 24.063% (77/320) | 22.656% (87/384) | 49.688% / 49.219% |
| **Equal net** | **0/320** | **0/384** | **25.313% / 26.563%** |

All equal-net targets retain four deposit candidates at withdrawal and after
the drain. Uniform selection among those four would succeed 25% of the time.
The fixed oldest/newest rankings perform near that comparator. Candidate count
is not a posterior probability, number of anonymous people or privacy score.

The primary paired 95% intervals for reduction in unique reconstruction versus
varied funding are 85.313–97.500 percentage points (sparse) and 75.260–91.927
points (burst). Against equal gross, they are 21.875–26.250 and 20.052–25.521
points. Both satisfy the preregistered inference screen. Intervals resample whole
paired ledgers 10,000 times; correlated notes/arms are not independent samples.

The separate note-creating-transaction attack still guesses correctly for 30.0%
and 21.615% of equal-net exits after drain. Equal funding does not hide all
payment relationships. The singleton stays unique, and the explicit early exit
before other funding stays unique. Shared funding leaves the four deposit
candidates but only **one funding cluster**.

## Why this works in the model, and its limits

Every deposit arrives before any private payment. All four begin with equal
private budgets, and every transfer can use any eligible prior note. Exchanging
the four deposit labels therefore leaves compatible histories. Equal gross
funding leaves the bootstrap fee difference, breaking that symmetry for some
withdrawals. The measured zero unique-deposit count has this structural
explanation; it is not 64 independent demonstrations of a new cryptographic
property.

Pairing selects payment inputs eligible in all three arms and maps a common
random split quantile to each arm's valid amount range. Payment amounts can
differ; this is a controlled common-topology workload, not three natural user
populations. Denominations vary between pools; this does not test different
denominations coexisting in one pool. There is no invented cover traffic or
extra waiting. Public labels use OS randomness rather than encoding trial seeds.
Seeds exist for reproducibility; recovering a published synthetic trial from its
seed is outside this experiment's fixed attack model.

"No added waiting" is relative to the paired schedules: the first sparse
depositor waits four synthetic hours before drainage starts, and the burst
schedule waits 45 minutes. This does not establish how quickly real users would
find compatible activity. TN10 validates the economic order with actual recorded
confirmation times; it does not replay those synthetic minute intervals.

The observer uses only public projections in an isolated process; the scorer
has the hidden consumption/value/ownership truth. It does not see wallet files,
generator, other arms, seed draws, IP/RPC logs, mempool timing or merchant data.
Commitments, encryption and proofs are assumed confidential. Native-byte
calibration checks decoding and the relation; it does not exhaust all byte-level
attacks, prove cryptography, establish independent-user anonymity, or audit code.

Interleaved funding/payments/exits, unequal amounts, external knowledge and use
of an old fallback can change this result. Matching deposits does not require
waiting for an operator to permit exits: an early exit remains allowed, with
the measured privacy cost. No minimum anonymity claim is a withdrawal lock.

## Validation and reproduction

The first equal-net case in each regime was realized with 58 genuine proofs in
total. Both saved and fresh alternatives drained: 17 native transactions per
sparse arm and 21 per burst arm, 44 withdrawal occurrences across those four
exclusive worlds. Exact decoded public fields, candidate sets and scores match
the model. These calibration transactions use synthetic ordinary UTXO contexts;
they do not spend test coins.

The additional native adapter checks ten isolated exits per saved/fresh arm and
nine rejection controls. Its final hash-recording path is exercised offline as
well. The 31 Python and 12 Rust library tests passed. The
[second-pass review](NORMALIZED-DEPOSITS-REVIEW.md) records rejection layers,
corrected harness defects and remaining assumptions.

| Calibration layout | Pool fees (sompi) | Ordinary genesis fee | Total tKAS equivalent |
| --- | ---: | ---: | ---: |
| Sparse, either proof arm | 351,039,200 | 204,900 | 3.512441 |
| Burst, either proof arm | 438,694,400 | 204,900 | 4.388993 |

At the configured 100 sompi/mass, a private transfer/bootstrap costs 21,893,200
sompi, admission 22,005,200 and full exit 21,934,400. Equalization adds no pool
transaction or fee. Ordinary funding preparation has separate, shape-dependent
fees; the actual TN10 totals below must not be replaced with this synthetic
genesis estimate. These are tested-layout fees, not a market quotation.

Calibration cold parameter load was 103.555 seconds; fresh exits took
9.631–13.656 seconds each (some under concurrent local test load). Normalization
does not require another proof beyond the existing fresh-proof/fallback policy.
Those components are not end-to-end wallet or network latency measurements.

## Actual TN10 outcomes and costs

The clean rehearsal and fresh measured trial each confirmed **18 transactions**:
one ordinary allocation, native genesis, bootstrap, three later admissions,
two private payments and ten full exits. All four wallets were paid; every
selected proof/authorization remained unchanged. Proving stopped before any
pool broadcast. Each exit process used its own capability and independently
fetched public history, with no wallet secrets, proving key or operator repair.
All accepted bodies/full hashes and remaining ordinary outputs reconciled.

The isolated observer decoded both accepted histories and recovered exactly the
model's source/note/deposit candidate sets. Each withdrawal still has four
funding-deposit candidates under the fixed attack. Their common allocator is
visible: this is one funding cluster, not evidence for four unrelated people.
The decoder's legacy `minutes` field holds dependency ordinals for these live
traces; actual chain timestamps and submission/confirmation times are retained
separately. No synthetic elapsed time is represented as a network measurement.

| Actual run/cost | Transactions | Fee (sompi) | Fee (tKAS) |
| --- | ---: | ---: | ---: |
| First funded rehearsal, recorder failure after all payouts | 18 | 352,417,800 | 3.524178 |
| Clean rehearsal | 18 | 352,417,800 | 3.524178 |
| Fresh measured trial | 18 | 356,999,900 | 3.569999 |
| Ordinary payout recycling, two batches | 75 | 20,595,000 | 0.205950 |
| **All actual H12 transactions** | **129** | **1,082,430,500** | **10.824305** |

Every pool's fee subtotal is 351,039,200 sompi (3.510392 tKAS). Each real
genesis cost 1,017,500 sompi. Ordinary allocation cost 361,100 in each rehearsal
and 4,943,200 in the measured trial, whose smaller ordinary change output raises
storage mass. That difference is funding layout, not a normalization charge.
All funds are test KAS; the offline model/calibrations spent no native funds.

The first funded rehearsal had already paid all ten claims and closed its pool
when the final recorder incorrectly expected full hashes in bare fee metrics.
A read-only repair reconstructed and verified all 18 accepted bodies/hashes;
there was no rebroadcast. It remains explicitly marked as a recorder failure.
A fresh clean rehearsal then passed the entire corrected path before the
measured trial. An earlier unfunded rehearsal was also stopped to improve the
negative controls; it broadcast nothing. Failed/partial raw runs remain private.

Decision: retain fresh proofs/private fallback and equal net credits as the
bounded candidate. Test interleaved arrivals and mixed amounts before general
privacy claims; preserve Stage 3–5 fee/failure/usability/review gates. No further
protocol change or upstream publication is implied. See
[ADR-0023](../../docs/adr/0023-equal-net-deposit-policy.md).

Sanitized [summary](evidence/2026-10-20-normalized-deposits/summary.json),
[native calibration](evidence/2026-10-20-normalized-deposits/native/calibration-summary.json),
[measured result](evidence/2026-10-20-normalized-deposits/tn10/trial/result.json)
and [export manifest](evidence/2026-10-20-normalized-deposits/export.json).

## Reproduce

Use the existing private parameter directory; never place it or generated
wallets/capabilities in Git. Model generation is one fresh directory per run:

```sh
python3 poc/shared-pool/normalized-deposits.py prepare /PRIVATE/STUDY
python3 poc/shared-pool/normalized-deposits.py evaluate /PRIVATE/STUDY
python3 poc/shared-pool/normalized-deposits.py native-inputs /PRIVATE/STUDY
python3 poc/shared-pool/privacy-study-native.py prepare /PRIVATE/STUDY/native
python3 poc/shared-pool/privacy-study-native.py analyze /PRIVATE/STUDY/native
```

The independent exit adapter can then exercise both saved/fresh drains offline.
Each process receives only its own selected capability and authenticated public
material. TN10 also fetches its own accepted history and checks current backing:

```sh
node poc/shared-pool/normalization-run.mjs new STUDY PARAMS PRIVATE_BASE
node poc/shared-pool/normalization-run.mjs offline STUDY PARAMS PRIVATE_BASE
node poc/shared-pool/normalization-run.mjs rehearsal STUDY PARAMS PRIVATE_BASE OFFLINE_RUN
node poc/shared-pool/normalization-run.mjs trial STUDY PARAMS PRIVATE_BASE OFFLINE_RUN REHEARSAL_RUN
```

`new` creates an unfunded identity in under a second on this host. Live commands
create new identities themselves; they do not reuse an earlier submitted run.
Proof generation is a separate, slower operation. The native build uses
`cargo +1.95.0 build --release --manifest-path poc/shared-pool/Cargo.toml --bin kpi-normalized-deposits`;
the runner accepts `KPI_NORMALIZATION_BINARY` for the resulting binary location.
Node requires the existing pinned Kaspa SDK through `KPI_SDK_PATH` if its local
default cache path is unavailable. Model requirements are in
[privacy-study-requirements.txt](privacy-study-requirements.txt).

The live funding utility recycles already paid ordinary test outputs; it has no
reserve-spend path. Its source-key lookup now handles note positions exceeding
transaction indices, still requiring exact public-script/key ownership. The
first preparation attempt exposed this old lookup assumption and failed locally;
no transaction was broadcast by that failed attempt.
