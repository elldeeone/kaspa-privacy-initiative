# Reconstruction after one participant discloses its records

H16 on `shared-pool-four-wallet`. Scope and input hashes were committed as
`5c44c55`, before implementation or observation.

**Outcome:** the frozen disclosure screen **fails**. A participant's records
force two additional early payment-source links even with fresh proofs.
Fresh still retains more payment alternatives in all sixteen matched
case/participant combinations and substantially fewer forced withdrawal links
than saved exits. Keep fresh normal proofs and private exit fallbacks. Prioritize
withdrawal-amount policy before expanding wallet features; strong privacy
remains unestablished.

## What this adds

H15 tested an observer who knew the chain and our wallet's construction rules.
This test additionally gives it one participant's complete, honest wallet
records. Each of the four wallets is disclosed separately; their records are
never pooled. Score only transactions with no input or positive output owned
by that participant. A recipient's later spend of a note previously sent by
the participant remains eligible: the participant does not already know that
later spend.

The four economic cases and eight fresh/saved public transcripts are copied
byte-for-byte from H14. Amounts, schedules, fees, deposits, private input choices
and drainage order are unchanged. No new cryptographic proofs or transactions
are generated. H14's genuine native calibration and independent saved exits
remain earlier evidence, not new H16 validation.

The [frozen specification](PARTICIPANT-PRIVACY-SPEC.md) requires all three:

1. No additional uniquely determined uninvolved fresh-policy payment source,
   compared with H15 on the same targets.
2. At least half of eligible fresh-policy payments remain ambiguous in every
   case/participant combination.
3. Fresh retains more marginal payment-source alternatives than saved in at
   least one matched combination.

These are a bounded disclosure screen, not Stage 2's population gate or a
definition of strong privacy. Any new forced link fails the first clause.

## Observer and scoring boundary

The observer receives public chain fields and one projected record:

- Positive receipts: note positions and amounts, including self-change.
- Its own authored transactions: real inputs, output values and equality of
  receive addresses it used, represented by local anonymous handles.
- Knowledge that its own notes were not spent in somebody else's transaction,
  assuming a complete record and an uncompromised account.

Receipt knowledge does not reveal incoming sender identity, sender inputs or
sibling plaintext. Sending a note does not reveal its later nullifier: that
requires the recipient's spending secret. No keys, openings, unused exit proofs,
other wallet views, global wallet IDs or four-owner limit are supplied.
At each checkpoint, future receipts and authored transactions are removed.

`records` adds these facts to H15. The primary `wallet` profile also assumes
same-author inputs, positive normal output 1 as sender change, and positive
partial-withdrawal output 0 as retained sender value. These are conditional
client behaviors, not circuit requirements. The ablation removes ownership
propagation; it does not separately isolate each ownership rule.

All predictions finish before the scorer opens hidden truth. Only the scorer
selects eligible targets. Chain-only H15 is a matched baseline; participant
knowledge is explicitly additional. RPC access, IP addresses, network timing,
external identities, human conversations and collusion are outside the test.

Metrics concern source-transaction sets and exact input-note sets. Alternatives
are marginal logical possibilities, not equally likely guesses, people or
joint histories. Several sources could belong to one already-known authority.
This test does not measure hidden-amount ranges or owner-identity ambiguity.

## Results

All 64 observations finish. All three frozen clauses are evaluated:

| Clause | Observed result |
| --- | --- |
| No new uniquely linked uninvolved fresh payment | **Fail:** two new links, one in each amount row of schedule 1. |
| At least half ambiguous in every fresh case/participant pair | Pass: all sixteen pairs; ambiguous counts are 3/3, 1/2, 3/4 or 4/4. |
| More fresh alternatives in at least one pair | Pass: all sixteen pairs; summed marginal alternatives are 835 fresh versus 390 saved. |

The following counts refer to **distinct economic targets across four synthetic
cases**, after complete drainage. A participant result means at least one of
the separate, eligible participant views uniquely identifies the source set.
It does not combine their knowledge into one observer.

| Target | Chain-only fresh | Participant fresh | Chain-only saved | Participant saved |
| --- | --- | --- | --- | --- |
| Private payments | 2/24 | **4/24** | 2/24 | **6/24** |
| Partial withdrawals | 0/8 | **3/8** | 0/8 | **4/8** |
| Full exits | 0/28 | **7/28** | 20/28 | **28/28** |

For the actual **overlapping participant-target observations**, the full-drain
metrics are:

| Profile and exit policy | Forced payment sources / 48 | Forced partial sources / 24 | Forced full-exit sources / 84 |
| --- | --- | --- | --- |
| H15 chain-only, fresh | 4 | 0 | 0 |
| Records, fresh | 6 | 2 | 6 |
| Records + wallet rules, fresh | 6 | 3 | 7 |
| H15 chain-only, saved | 4 | 0 | 60 |
| Records, saved | 8 | 4 | 72 |
| Records + wallet rules, saved | 8 | 4 | 72 |

Every forced link is correct in these fixtures; the attack abstains on other
targets. Primary fresh has 1–49 remaining payment-source sets, 1–44 partial
sources and 1–9 full-exit sources; saved has 1–21, 1–16 and 1–5 respectively.
Exact input-note sets remain ambiguous for all 48 payment observations, including
those with one source transaction. Exact inputs are unique for 3/24 fresh partials
and 7/84 fresh exits, versus 4/24 and 36/84 saved.

The deterministic recency guess, which does not abstain, correctly selects
payment/partial/exit source sets on 10/48, 9/24 and 32/84 primary fresh observations,
versus 16/48, 10/24 and 84/84 saved. These are attack results on overlapping
fixtures, not probability estimates.

At appearance, primary fresh has six forced payment observations, zero partials
and three exits. At full drain it still has six forced payments, but three
partials and seven exits. Twenty of 48 fresh payment observations narrow later;
none becomes newly unique. Saved narrows 38/48 and makes two further payment
observations unique. Thus fresh helps preserve payment ambiguity through the
later activity, while some withdrawal links remain exposed.

The same economic transaction appears in more than one eligible participant
rotation. Report overlapping observations and distinct economic targets
separately. A distinct target linked by at least one participant does not mean
one participant can link every such target.

Payment horizons are appearance, subsequent full-exit checkpoints and complete
drainage. The first exit checkpoint for an early payment also includes intervening
payments and partial withdrawals. First detection at that checkpoint does not
establish that the exit alone caused the link.

See the [frozen-clause summary](evidence/2026-10-20-participant-reconstruction/summary.json),
[aggregate observations](evidence/2026-10-20-participant-reconstruction/aggregates.json),
[distinct-target derivation](evidence/2026-10-20-participant-reconstruction/derived-metrics.json)
and [file hashes](evidence/2026-10-20-participant-reconstruction/SHA256SUMS.json).

## Decision

**Retain the compact settlement design and fresh normal authorizations/private
fallbacks as research candidates. Do not treat this as passing Stage 2.**
The study identifies two different problems:

1. **Startup:** in schedule 1, the disclosing participant funded the only
   admission before the first payment. It knows its own note was not spent.
   Excluding that admission leaves the bootstrap transaction as the sole source:
   three H15 source sets become one. This is already visible at payment appearance
   in both amount rows, under `records` alone. Later exits cannot undo that leak.
   The diagnostic grouping is post hoc; it does not change the failed criterion.
   A nearly empty pool has no alternative unknown source to hide among.
2. **Later withdrawals:** under fresh proofs, records alone force six full-exit
   links and two partial-withdrawal links across the distinct targets. The added
   ownership rules force one further partial and one further exit
   (`a0-s1`, participant 0, events 8 and 16). Removing only those ownership
   assumptions therefore leaves most measured withdrawal links intact. This
   does not support treating output-order randomization alone as a sufficient
   remedy. These are deductions from the tested ablations, not a new mitigation
   experiment or a minimal causal explanation for every link.

**Recommended next bounded question:** can common-size partial payouts with
private remainder reduce the links from withdrawals back to original payments,
through complete drainage, compared with full-note cashouts?

Use the existing v6 partial-withdrawal mechanics and fresh normal proofs. Keep
the same economic obligations, one-participant observer and private independent
fallback; account for every added fee and eventual remainder. Freeze one payout
size before observation, compare with the retained baseline, and score links
to the original payments rather than counting extra self-change outputs as new
independent privacy. Preserve amount/floor limits and an immediate independent
exit; waiting for others must never become an exit condition.

This is a proposed wallet-policy investigation, with **unmeasured benefit**.
At the fixture's selected fee, each extra operation costs 40,000,000 sompi
(0.4 tKAS), plus proving and confirmation work; actual cost depends on the chosen
schedule. Reject the policy if the gain disappears after final remainders,
depends on hidden invented traffic, or costs more than a predeclared budget.
No new protocol, token, consensus primitive or privileged actor is required
to ask this question. No follow-up is implemented or run here.

A startup policy must separately explain that available chain activity does not
prove a number of independent people. Other genuine, compatible funding can
provide alternatives; merely waiting, creating more addresses or self-paying
cannot guarantee them. Do not promise a numeric anonymity level from these
four-wallet fixtures.

## Validation and access-boundary correction

The run includes 28 controls. Two additional partial-change controls were added
during observation, before scoring; all 30 pass. The tiny-ledger independent
oracle is compared with integer CP-SAT, integer SMT and the hybrid search.
Controls cover conditional ownership, receive-only knowledge, zero padding,
record projection, malformed/replayed records, anonymous owner assignments and
knowledge available at earlier checkpoints.

The main scorer checks that truth survives every reported horizon, including
participant-owned targets omitted from headline metrics. Candidate sets must
nest: primary inside records inside H15; saved inside fresh. A separate audit
fixes the original integer amounts and complete input graph at every prefix.
This is model validation, not proof of cryptographic correctness.

A second pass found an access-boundary flaw in the inherited sandbox: supervisor
arguments and `/proc` mount metadata exposed host paths containing case/policy
labels. Observer code did not read those surfaces; full private files and other
wallet views were not exposed. The first attempt was stopped without scoring
after 30 completed predictions and retained privately.

The corrected run omits `/proc`, runs the observer as namespace PID 1, drops
capabilities and denies nested user namespaces. Each observation checks those
restrictions and loopback-only networking. The public inputs, projected records
and observer equations are unchanged. H14/H15 numerical results remain retained,
but their isolation receipts should not be read as protection against arbitrary
process-metadata inspection. See the [self-review](PARTICIPANT-PRIVACY-REVIEW.md);
this is the implementing agent's second pass, not an independent audit.

The final audit passes **1,216 complete original amount/input-graph prefix
checks**, all 64 corrected isolation receipts and byte-identity checks for every
projected view. All 30 completed earlier predictions have identical candidate
rows in the corrected run. Source/evidence hashes remain valid. The three
nesting comparisons each check 3,168 candidate sets. An additional direct
CP-SAT check at `a0-s0/fresh`, participant 0, event 11 through 17 agrees exactly
on all thirteen feasible input sets, using 171 queries in 65.71 seconds.

An optional direct-CP performance diagnostic at a different slow checkpoint
(`a1-s1/fresh`, participant 0, event 16 through 16, both profiles) was stopped
after 570.48 seconds without either result, once the complete main run and its
required audit had finished. It is **inconclusive** and contributes no candidate
or score. Its [receipt](evidence/2026-10-20-participant-reconstruction/optional-integer-diagnostic.json)
and exact probe code are retained. It is not one of the 64 observations or 30
completed control tests.

## Cost and reproduction

Actual tKAS spent: **0**. New proofs: **0**. Added native fee and wallet delay:
**0**. The unchanged model still selects 40,000,000 sompi per pool operation,
760,000,000 sompi per nineteen-operation arm, excluding ordinary funding/setup.
That is 7.6 hypothetical tKAS per arm, not expenditure in this study or a current
fee quotation. Synthetic ten-minute spacing adds no unseen background traffic.

The corrected 64-observation run, including its initial controls, took
**67 minutes 30.30 seconds** with ten workers. Individual observations took
3.865–3,456.628 seconds. The largest child-process RSS high-water value was
484,076 KiB (about 473 MiB), not aggregate concurrent RAM. The interrupted attempt
consumed another 1,377.87 seconds; the final witness audit took 4.77 seconds.
These are observer costs, not wallet proving costs or evidence that a better
attack would be expensive.

From this directory, with the pinned solver environment:

```sh
python3 participant-privacy.py prepare "$KPI_H16_PRIVATE" "$KPI_H14_ORIGINAL"
python3 participant-privacy.py run "$KPI_H16_PRIVATE" --workers 10
python3 participant-privacy.py export "$KPI_H16_PRIVATE" "$KPI_H16_EXPORT"
python3 participant_privacy_report.py "$KPI_H16_EXPORT" "$KPI_H16_EXPORT/derived-metrics.json"
```

Use fresh output directories. The original H14 execution directory contains the
retained public inputs and separate private plans/truth; `prepare` verifies their
frozen hashes rather than generating a new workload. The supplementary tests
use the solver environment's Python with
`-m unittest participant_privacy_partial_tests -v`.
`participant_privacy_validate.py FINAL_ROOT EARLIER_ROOT` additionally audits
this corrected run against the retained interrupted attempt.

The sanitized export retains scored-target predictions, scores, hashes, controls
and isolation receipts. Raw participant records, full predictions of already-known
activity, keys, note openings, private plans/truth and unused capabilities remain
outside Git. Published scores can be summarized without those private files.

This is a synthetic, conditional inference study. It does not establish
real-world anonymity, cryptographic security, general exit liveness or mainnet
readiness.
