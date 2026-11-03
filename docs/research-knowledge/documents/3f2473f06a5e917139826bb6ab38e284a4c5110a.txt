# Owner-private native KAS prototype

2026-10-24. **Unfunded research. Financial integration passed locally; financial
privacy remains unqualified.** All 16 independently generated grouping worlds
completed under the frozen protocol, strategy and analysis rules.

## What changed

The previous construction exposed which two outputs belonged to each action.
This prototype separates Spend and Output proofs and mixes all six complete
output tuples through the selected malicious MPC engine. Public Spend statements
authorize the common financial effects without an output subset, individual
beta/beta-point, native owner public key or per-owner authorization signature.
Input-owner labels and other declared public metadata remain visible.

The coordinator is a separate isolated public process. It receives no owner
directories, Docker socket, host home or execution-request interface. Its
same-host launcher, daemon and selected software remain trusted; this is not
an independent-operator or malicious-host privacy result.

The initial external reviewer found missing financial verification, a foreign-
domain validation gap and variable private input lengths. The [disposition](EXTERNAL-REVIEW-DISPOSITION-01.md)
records the source changes. Spend/Output relations and the native bridge are
now implemented and genuinely exercised. Owner transport is fixed at 2,695
bytes; per-party completion times are absent from coordinator IPC. A separate
source-level cancellation counterexample led to replacing the initial stock
shuffle with existing random-key oblivious sorting. No complete network attack
is claimed from that counterexample.

## Genuine financial path

Three isolated owners each created two genuine Output proofs, then the actual
three-party Source04 MPC run completed in 88.27 seconds with identical results.
Each owner checked its own engine result, complete pool, delivery, roots, fees
and balance before producing its genuine Spend proof. Both the accelerated
predicate and independent Arkworks pairing reference verified all nine proofs.

The owner rejected a changed canonical Delta before authorization; the correct
unchanged projection then succeeded for all three owners. An actual repeat
authorization after the durable barrier was rejected without a new export.
The original valid authorization remains capable of settling; rejection or
timeout does not revoke it.

The new guest executed all nine proofs in **487,068,688 cycles / 8.603 seconds**.
Actual GPU succinct proving took **1,854.358 seconds**, followed by genuine
compression and separate CPU receipt verification with development mode and
unresolved assumptions absent. The resulting 128-byte proof passed actual
Native077 Full validation and the individual script engine.

| Local native result | Observed value |
| --- | ---: |
| Fee, integer sompi | 19,332,300 |
| Transaction mass | 193,323 |
| Reference fee rate | 100 |
| Script units | 15,548,275 |
| Declared script allowance | 18,009,999 |
| Native payouts | 0 |

One genuine public positive and **42 changed/malformed host inputs** were
checked. All 42 negatives were rejected. The actual native harness accepted
the genuine case and rejected **12 canonical mutations using the same proof**:
two integrity errors and ten native policy errors. The earlier duplicate-output
fixture's negative-fee rejection is retained separately; a fee-preserving split
isolates the final output-count control. Tests do not prove cryptographic
correctness or production safety.

Key joins:

- Final projection: `d971317a4b17d1ef0f0967155cb412360924f1fcc165298942103e33c3f30e55`.
- Effects: `0a1d2fbb02b6e4a65304a717f9e8da6d2b06e6822d6757e27965490ab9c1fe08`.
- Journal104: `9253d67b3cc2f81f3f6f2a1c52985cbd1e4e8fa8428cdc033c308bcaa0c3a6e1`.
- New image: `797bc8c94159c0d159887578d5c3f33c7b354f68b3392a3d80b3303322ae93b2`.
- Native proof128: `77789708f4ff8e1951d23d60c9d19716e927688a7be73208dbe1c8eb8c6a309c`.
- Native 13-case result: `261de7a53d2aae52331b2f8841669b5dba07f1ab9fe2afdde909cd7e728be816`.

The [execution evidence](execution-01/MANIFEST-01.json),
[outer packet](execution-01/outer/MANIFEST.json) and
[native result](../../../poc/owner-private-payments/verification/RESULTS-01.md)
identify separate evidence levels. The native result uses supplied UTXO contexts;
it does not establish funding, accepted backing, currentness or confirmations.

## First privacy observation, retained

The [frozen first experiment](PRIVACY-EXPERIMENT-01.md) kept all honest truth
inside owner workers. One permitted colluder used its own created outputs,
openings/beta and legitimately decrypted incoming notes, including actual
invoice issuance knowledge under the selected honest-worker assumptions.
Predictions and ambiguity were sealed before one count-only query per owner.
The host never read or hashed capsules, private counts, seeds or ownership maps.

| Frozen view | Exact creator-label matches | Complete groups matched |
| --- | ---: | ---: |
| Coordinator baseline | 2 of 6 | 0 of 3 |
| One colluder, unknown targets only | 3 of 3 | 2 of 2 |

The colluder already knew three creator facts and chose among **three presealed
admissible partitions**. Its correct guess is retained. It was not a unique
constraint-derived recovery, and one small trial cannot establish either a
reliable leakage channel or anonymity. Swapping honest creator labels cannot
hide a successful group prediction in the scorer.

## Independent-world cohort

[COHORT-CONTRACT-01.md](COHORT-CONTRACT-01.md) freezes 16 new worlds before any
cohort owner initialization. The exploratory result above is excluded. Every
world creates fresh seeds, notes, choices, blindings, session and actual MPC
randomness, completes nine genuine component proofs and independent host
verification, then performs one sealed diagnostic query per owner.

The primary event is recovery of both eligible honest groups in one world.
An exact rational Poisson-binomial comparison uses the presealed partition
count K_i and idealized chance p_i=1/K_i, with alpha 0.01. Conditional-uniform
hidden grouping and independent worlds are explicit baseline assumptions, not
proven protocol properties. Missing worlds stay incomplete; no score-based
dropping, replacement, early stopping or strategy tuning is allowed. No outcome
of this bounded cohort qualifies financial privacy.

All **16 of 16** worlds completed in **38.33 minutes**, without replacement,
incomplete slots or candidate-failure verdicts. They generated 96 genuine Output
and 48 genuine Spend proofs, with independent nine-proof verification in every
world. No per-world outer proof, native acceptance or chain confirmation is
implied by those component checks.

The frozen colluder strategy recovered both eligible honest groups in **4 of
16 worlds**. Thirteen presealed worlds had K=3 and three had K=2. The idealized
chance expectation is 35/6 successful worlds; the exact upper tail at four is
**474353/531441**, above the frozen 0.01 threshold. No excess success was detected
for this strategy against that model. The [independent closed-form check](COHORT-ACTUAL-MATH-CHECK-01.json)
matches the runner's rational calculation. This tail is not a probability that
the protocol is private, and the result does not qualify privacy.

The [uniform evidence plan](execution-01/cohort/SELECTOR-PLAN.json) selected
162 public files before reading secondary outcomes. All primary world events,
genuine projections/journals and matching proof reports are retained in the
[cohort manifest](execution-01/cohort/MANIFEST.json). Per-world secondary
coordinator scores and their low-entropy hashes are deliberately excluded
uniformly: confirming a fixed public guess as 6/6 could itself publish the
actual research mapping. Raw secondary records remain outside the publication
set. This changes neither the 16-world denominator nor the frozen primary test.

Source: runner `08cbbb13c14a759c100c80207ec30232d8ff14e28af939a352b7049d0c0fc49a`,
spec `c992a5931f358affadda7d76af9b88356a667765263175a95ed72914ec31d511`.

## Remaining boundaries

This new domain has no executed deposit/backing path, repeated spending,
receiver backup recovery or independent exit. It does not inherit those
properties from the earlier funded four-wallet profile. P0 has one supplied
reserve, one continuing reserve, exact fee and zero native payout. Do not fund
this explicitly unfunded profile.

Output proofs bind ciphertext hashes, not encryption correctness. Recipient
decryption and note/CM/invoice checks remain required. Public amount/prior,
timing, endpoint, invoice/collusion, ancestry and transparent entry/exit
limitations remain. Three owners are a small anonymity set even when an
explicit grouping certificate is removed. Durable data/PK availability,
independent operators, broader active-adversary coverage and a cryptographic
composition review remain open.
