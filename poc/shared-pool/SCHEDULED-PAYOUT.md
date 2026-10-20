# Independently scheduled common payouts

Status: complete. **The frozen offline gate fails on privacy.** Fee and delay
limits pass. Do not adopt this short-delay policy as a privacy improvement;
the condition for native calibration and TN10 was not met. No funds were used.
The [scope and gate](SCHEDULED-PAYOUT-SPEC.md) were committed in `b3fe70e`,
before implementation (`de2eeb5`) and workload generation.

H17 used four common payouts before all final exits, with ten-minute spacing.
H18 tests whether the benefit survives local withdrawal requests and timers:
2 tKAS now, a private remainder, and an optional full remainder exit after
5–15 minutes. Immediate independent exit remains available. There is no
shared round, new traffic, privileged coordinator or protocol change.

## Result and decision

The strongest of the three fixed guessing attacks succeeds equally often in
both arms, in both activity regimes. All guesses cover every eligible original
cashout claim. A correct guess on either leg counts as a successful attack.

| Activity / observer | Correct guesses, ordinary full exits | Correct guesses, scheduled partials | Required reduction |
| --- | ---: | ---: | --- |
| Overlapping / chain only | 22/84 | 22/84 | Not met |
| Overlapping / separate participant views | 93/252 | 93/252 | Not met |
| Sparse / chain only | 23/84 | 23/84 | Not met |
| Sparse / separate participant views | 95/252 | 95/252 | Not met |

These are synthetic source-guessing results, **not percentages of privacy**.
The participant totals aggregate four separate observers, never combined
records. The recency attack wins the family comparison in each row; the
timing-graph attack is not presumed best merely because it is more complex.
All individual attack results are retained in
[summary.json](evidence/2026-10-20-scheduled-payout/summary.json).

The relative reduction is zero in all four comparisons. Paired whole-ledger
95% intervals for absolute improvement, in percentage points, are respectively
`[0, 0]`, `[0, 0.794]`, `[-2.381, 0]`, `[-3.175, 0]`. None establishes the
required improvement. The result also creates no new uniquely inferred
original-payment source in any matched case/view.

| Cost per primary paired ledger | Ordinary full exits | Scheduled partials |
| --- | ---: | ---: |
| Pool operations through full drainage | 19 | 23 |
| Modeled pool fees, tKAS | 7.6 | 9.2 |
| Added fee | — | 1.6 tKAS / 21.05% |
| p95 added completion delay, each regime | — | 16 synthetic minutes |
| Maximum added delay, overlapping / sparse | — | 18 / 17 synthetic minutes |
| Final reserve | 0 | 0 |

All four modeled wallets receive positive payouts in every primary arm. These
fees include every modeled payment, deposit, partial and final pool exit.
Ordinary funding allocation/genesis are not simulated; these are neither a
complete live funding budget nor current fee quotes. Actual tKAS spent is zero.
The 25% fee and 30-minute p95 delay limits pass, but cannot compensate for a
failed privacy requirement.

**Decision:** stop this continuation before native/TN10. Keep the existing
payment, private-change and independent-exit mechanisms. Reject this particular
2-tKAS/5–15-minute policy as a demonstrated practical privacy mitigation.
Stage 2 remains open. Do not retune these seeds, delays or denomination and
relabel the result a success. A next design decision must address the tradeoff
between prompt complete cashout and overlap with other activity, before another
wallet implementation or live trial.

## What the observer learned

Under the declared clock/queue and normal-wallet assumptions, each of the
48 common payouts in the sparse regime has exactly one time-compatible final
remainder. Every such pairing agrees with hidden truth. Pairing the legs lets
the observer add the two payouts and both fees to recover the original note's
value. Every leg's original-source candidate set then equals its ordinary
full-exit counterpart in all 336 eligible claim/view comparisons. This does
not mean the original source is always uniquely known: chain-only candidates
still range from seven to nine creating transactions.

In overlapping activity, only 5/48 common payouts have a sole compatible tail;
the median is three possible tails. Some candidate sets widen: the median
claim candidate count across separate participant views rises from six to
seven. Nevertheless, this does not reduce the winning attack's success.

Uniquely forced original cashout sources remain 0/84 chain-only and 24/252
separate-participant observations in each regime and arm. Those participant
links concern 24 distinct claims out of 84 in each regime, not 24 collaborating
people. Original-payment unique-source observations also remain unchanged:
3/72 and 4/72 chain-only, and 7/144 and 9/144 across separate participant views,
for overlapping and sparse activity respectively.

The earlier H17 improvement does not generalize to these new frozen workloads.
Even the inherited model without the additional scheduling restrictions
retains the same 24/252 unique participant claim observations in each arm.
Therefore the failed gate cannot be attributed to timestamps alone. The
ablation removes both timing compatibility and the no-re-splitting rule;
it is not a pure timestamp experiment. Aggregate checks are retained in the
[post-score audit](evidence/2026-10-20-scheduled-payout/derived-audit.json).

## Validation and execution

- All 252 complete observations precede primary truth scoring. All 504 exact
  original amount/input-graph checks pass; true sources remain in every
  candidate set. All 2,304 scored narrowing checks pass.
- Nine controls pass, including exhaustive tiny ownership/value/source and
  maximum-objective comparisons. They pass again under the replay's solver
  setting. A separate post-partial escape control confirms that immediate
  change withdrawal remains valid outside the optional normal-timer model.
- The singleton control links both claims in both arms. The immediate override
  retains two saved-anchor claims in each arm. These are arithmetic/observer
  controls, not newly generated private exit proofs.
- One initial two-worker observer exhausted host memory before output. The
  other 251 completed predictions were retained. The identical stalled query
  solves in 0.16 seconds with one worker; the incomplete observation then
  completes in 14.37 seconds, with unchanged constraints, objectives, source
  inputs and certificates. The original failed attempt and diagnostic replay
  are retained privately. No timeout, missing case or favorable rerun enters
  the score. See the [recovery receipt](evidence/2026-10-20-scheduled-payout/solver-recovery.json).
- Frozen scope bytes, all original execution sources, previous H17 manifests,
  the v6 circuit/covenant and dependencies remain unchanged. The extra replay
  wrapper is explicitly identified by its own hash.

The [evidence manifest](evidence/2026-10-20-scheduled-payout/SHA256SUMS.json)
binds public transcripts, eligible predictions, scores, isolation receipts,
costs and controls. Post-score aggregates are derived from private truth;
they were not observer inputs. Raw private records/views, seed, request files,
keys and unused capabilities are excluded.

## What the comparison can decide

Twenty-four new paired ledgers reuse the six-payment topology with new amounts,
legal event orders and withdrawal requests. Twelve have overlapping low activity;
twelve have a quiet period and sparse requests. Singleton and immediate-exit
controls are separate. All tails, fees, interleaving and reserve drainage count.

The chain-only observer and each of four separate participant observers know
the client rules. The inherited integer reconstruction is compared with the
schedule-aware model, which adds both no re-splitting of common change and
elapsed-time compatibility. That ablation does not isolate those two additions.
Full-coverage guesses use a fixed uniform reference, recency and a
globally consistent maximum timing-score graph. All predictions finish before
hidden truth is opened for scoring; no timed-out search counts as privacy.

Each original cashout claim remains one target. If either leg is correctly
guessed, the observer succeeds on that claim. The score does not give observers
the secret leg association or pool separate participants' records. A source
means the transaction that created the original note, not a person.

The gate requires a 25% relative reduction in the fixed attack family's
full-coverage success in both regimes and observer profiles, with paired
whole-ledger intervals excluding no improvement; no new unique payment links;
at most 25% extra pool fees and 30 minutes p95 added completion time.
A small study may fail or be inconclusive. Either stops before funding.

## Timing and native evidence boundaries

The public `minute` field is a synthetic chain-time proxy, not a new transaction
field or measured mempool/RPC acceptance timestamp. The model assumes a common
clock and a two-minute work-conserving service allowance. Its integer delay
bounds do not establish accuracy under real block-time variation, clock skew,
fee competition or confirmation delays. A conditional TN10 trial must measure
the actual timings; it cannot claim that this model established live latency.
The timed observer also conditions on the normal schedule being followed.
An immediate change exit after a partial is valid under the original relation
but can be outside that model; a separate escape control checks this distinction.
No timed singleton is a universal inference about every permitted v6 history.

Existing v6 circuit, covenant, setup and settlement are unchanged. H17's genuine
proofs and isolated independent exits remain earlier evidence. H18's new
offline observer and scheduling controls do not constitute another native or
cryptographic validation. The failed offline gate means no new genuine
calibration, live adapter, funding, rehearsal or measured TN10 trial was performed.

No RPC/IP access, collusion, real-world traffic, empirical anonymity or
independent cryptographic audit is supplied. A positive maximum-score attack
result is an observed heuristic result, not a calibrated posterior.
Public hash scores break objective ties, but do not guarantee a unique optimal
graph. The retained predictions identify the actual selected guesses; solver
thread scheduling can affect a remaining exact tie.

## Reproduce

The private seed file is outside Git; its hash is committed in the freeze.
Private records, generated request times and claim matching never enter the
observer namespace. Public exports omit those inputs and unused capabilities.

```sh
cd poc/shared-pool
python -m unittest -v scheduled_payout_tests
python scheduled-payout.py prepare "$KPI_H18_PRIVATE"
python scheduled-payout.py run "$KPI_H18_PRIVATE" --workers 4
# Only if the run has exactly one incomplete observation, as this run did:
python scheduled-payout-replay.py "$KPI_H18_PRIVATE"
python scheduled-payout.py score "$KPI_H18_PRIVATE"
python scheduled_payout_audit.py "$KPI_H18_PRIVATE" "$KPI_H18_PRIVATE/derived-audit.json"
python scheduled-payout.py export "$KPI_H18_PRIVATE" "$KPI_H18_PUBLIC"
```

Use `privacy-study-requirements.txt` in the existing tools environment and a
fresh private directory containing the committed-seed-matching
`master-seed.bin`. That private seed and participant records are intentionally
not published. Chain-only observations can be repeated from the public
transcripts; exact participant reruns require their private records.
Creation is exclusive; existing evidence is not overwritten.
Per-job source snapshots, input digests and namespace receipts identify the
actual execution. The [second pass](SCHEDULED-PAYOUT-REVIEW.md) records the
author's adversarial review, and the
[source refresh](../../research/scheduled-payout-sources-2026-10-20.md) separates
this branch's experiment from current upstream work.
