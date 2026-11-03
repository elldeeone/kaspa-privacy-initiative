# H15: reconstruction with known wallet behavior

Frozen before running the new observer. Baseline `fe5514b`, branch
`shared-pool-four-wallet`. Owner authorization: implement and run offline using
H14's same frozen workloads, compare fresh/saved through drainage, retain code,
results and journal on this branch. No protocol change, new proofs, TN10 run,
funding, push or publication is part of this study.

## Question and decision

Does H14's modest ambiguity screen survive an observer who knows this
prototype's transaction-construction defaults? H15 applies the same threshold:
after full drainage, at least three of six private payments in **every fresh
case** must have more than one feasible source-transaction set, and fresh must
leave a strictly larger sum of marginal source-set counts than saved in at least
one pair. Failure rejects the present wallet profile as sufficient for this
screen and requires a privacy redesign before expanding wallet features.
Passing retains it for research; it establishes neither strong privacy nor
real-world anonymity. Report each result even if the overall screen fails.

`wallet-policy-privacy-freeze.json` pins the code supplying the rules and every
public input. Reuse all eight H14 transcripts byte-for-byte and the original
private scoring truth. Do not regenerate amounts, opaque identifiers, schedules,
destinations or proofs. Keep the first frozen workload commit `1bf14d0` intact.

## Exact additional knowledge

These are **conditional assumptions about the known client**, not consensus
constraints or a statement that all users follow this client. The observer gets
no policy-arm label, wallet identity, input choice, secret, private amount,
recipient schedule, drain order, workload manifest or truth.

| Rule | Code evidence at `fe5514b` | Constraint |
| --- | --- | --- |
| Admission places all net credit in slot 0 and padding in slot 1 | `two_input_privacy_generate.py:build`, `harness.rs:demo` admission construction | ADMIT output 1 has value zero; output 0 therefore equals public deposit minus fee. |
| Partial withdrawal puts retained private value in slot 0 | `two_input_privacy_generate.py:build`, `harness.rs:demo` partial construction | SPEND with public payout has output 1 zero. Keep one or two real inputs possible. |
| Full-note exit consumes one real note | `harness.rs:fallback` passes one `selected` input | DRAIN selects exactly one positive note. Its value equals public payout plus fee. |
| Fallback is created at receipt; fresh authorization uses current root | `harness/study.rs:run`, receipt fallback creation and fresh drain construction | If a DRAIN anchor is older than current commitment count, its input was born in that anchor's creation batch. If anchor is current, allow either fresh or receipt-time use. Never tell the observer which arm it sees. |

Birth count for an output is its creating transaction's `count_before + 2`;
genesis birth count is one. No commitment is appended by DRAIN, so multiple
exits can share a current root. Root age alone must not identify these as saved.

The public code has no automatic oldest/largest-first coin selector. Private
plans choose normal inputs and recipients. Do not reinterpret those choices as
public rules. Payment output 1 is intended as sender change, but its hidden
owner is not a public label. Same-owner input/change equalities alone cannot
exclude an unlabelled history when all notes could belong to one owner; do not
invent distinct-owner facts from distinct funding keys. Do not assume every
payment uses two inputs or every partial withdrawal uses one. Do not assume
every payment has two positive outputs. Positive values and dummy slots retain
the v6 range/floor semantics.

## Comparisons and controls

Use the recorded H14 protocol-only results as the baseline. Run two new profiles
on all four pairs:

1. `shape`: fixed admission/partial padding and single-note full exits.
2. `wallet` (primary): all shape rules plus the fresh-or-receipt anchor rule.

This ablation distinguishes amount/shape leakage from receipt-anchor leakage.
All rules apply uniformly, without inspecting prediction correctness. Reuse
H14's exact integer conservation relation, targets, deterministic recency rank,
and observation points: each spend at appearance and final drain; each of six
payments after each full exit. Report candidate real-input sets and deduplicated
sets of creating transactions, correct guesses, unique-source coverage/precision,
and retroactive narrowing. Compare all new sets with H14 and require nesting:
wallet subset of shape subset of protocol. Guess accuracy need not be monotone.
Counts remain marginal logical alternatives, not joint histories or likelihoods.

Every true set must survive each profile and reported prefix. Scoring opens
private truth only after an isolated observer writes predictions. Run in the
existing filesystem/network sandbox with only public input, observer code and
solver libraries. Keep controller, generator, manifest, truth, host home, wallet
keys and unused fallbacks inaccessible. Publish access probes and source hashes.

Before main scoring, compare both policy encodings and the final exact engine
with independent exhaustive tiny integer ledgers. Cover zero padding, one-note
drains, old versus current anchors, symmetric alternatives, impossible and
policy-violating histories, and earlier-prefix information boundaries. An
intentional policy violation must be feasible in the protocol model and
infeasible under the corresponding assumed rule. Check valid policy transcripts
are never excluded. Unknown/unfinished solver results are inconclusive, never
extra privacy. Retain incomplete attempts and record corrections without
changing workloads or the frozen policy.

## Cost, completion and boundaries

Complete all sixteen new observations, report all four primary paired outcomes,
and update the journal/plan with the resulting decision and one narrow next
question if needed. Include a second-pass adversarial review. Actual funds and
new proof work are zero. Native fees, proof timing, independent exits and genuine
calibration are inherited from H14, not newly demonstrated here. Hash-check the
unchanged circuit/covenant and existing calibration; do not rerun expensive
proof generation for an observer-only change.

The same synthetic schedules, unrelated-funder assumption, fresh addresses and
cryptographic-hiding assumption remain. Real users, network/RPC linkage,
cryptographic byte attacks, external identity labels and realistic timing are
not tested. A known-client attack is conditional on correct client attribution;
it is not unconditional consensus-level deanonymization. These frozen recipes
are public to a reader of the repository, so technical blinding applies to the
observer process, not the researcher or a reader given the recipes.

Source review: [H14](TWO-INPUT-RECONSTRUCTION.md),
[RFC-0011](../../docs/rfc/0011-two-input-private-payments.md), and the
[established-system review](../../research/compact-policy-study-sources-2026-10-20.md).
[ZIP 315](https://zips.z.cash/zip-0315) (Draft, refreshed for this study) treats
wallet behavior as part of privacy; [ZIP 224](https://zips.z.cash/zip-0224)
distinguishes real and dummy actions. Neither transfers Orchard security to v6.
