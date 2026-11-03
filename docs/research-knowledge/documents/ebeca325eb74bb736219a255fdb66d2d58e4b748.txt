# Stronger practical privacy screen: completed result

Date: 2026-10-21 UTC. Native candidate: `52c209296184d880221432fcbf56bb20d3f64d10`.
Frozen [specification](POPULATION-PRIVACY-STRONG-SPEC.md),
[source review](../../research/shielded-kas-strong-privacy-screen-2026-10-21.md),
[RFC-0014](../../docs/rfc/0014-owner-aware-privacy-evaluation.md), and
[retained evidence](evidence/2026-10-21-strong-privacy/README.md).

## Result and decision

**The completed attacks found no decisive privacy break in this workload. This
is not a privacy pass.** All 16 fresh histories completed, with 32 modeled users
and eight active colluding users per history. The strongest tested variant added
only five correct sender guesses, three recipient guesses and five amount guesses
within 10% over the frozen prior, across 968 primary eligible payments.

The exact frozen outcome is `bounded-screen-complete-no-certified-breach`.
There were also no raw point-estimate cap exceedances in the declared primary
comparisons.
`qualification_pass` remains false. The small number of independent histories,
limited attack family and synthetic observation surface leave the early privacy
gate open. Retain the candidate for further testing; this result provides no
reason to adopt a new wallet policy or advance dedicated milestone 3 work.

## What was frozen and executed

The specification, attacks, scorer, workload, runner, dependencies and source
review were copied and hashed before hidden seeds were sampled. Controls passed
before generation. No held-out seed was replaced, request skipped, attack retuned
or failed history discarded. All sixteen prediction files were sealed before
any private scoring. Observer processes received one public history, the pooled
records of the eight adversaries and the published policy, with no truth, other
histories, home directory or network access.

| Checkpoint | Identity or UTC time |
| --- | --- |
| Freeze | `1fdbd5c8a20a475578490161c4eff8c0c437f1adc5ead0a9db6ac724eecd5cf9` |
| Frozen | 2026-10-21 00:19:54.803836 |
| Controls completed | 2026-10-21 00:21:30.763196 |
| All predictions sealed | 2026-10-21 00:23:19.169537 |
| Batch completed | 2026-10-21 00:33:35.303047 |
| Prediction batch SHA256 | `08ce84a0439f3b5ad1077c7725f4657cc5c364cb83b21b477ba58a522a7b0b15` |
| Aggregate SHA256 | `dcf48d7cb58dcbc3f696c3de9986ea9241325de8fc43c196386d02737330667a` |

The histories contain four payment rounds per role, retained incoming balances,
variable 10–1,000 tKAS honest payments, nonadaptive adversarial amount tags,
staged admission and complete final drainage. Eight histories overlap; eight add
modeled quiet gaps. All 2,048 ordinary payments were predicted. The primary
predicate selects 968 honest-to-honest payments created after all 32 roles were
admitted: 486 overlap and 482 sparse. Startup and adversary-endpoint diagnostics
remain separately available in the aggregate; their denominators overlap and
must not be added together.

Exclusion matters: the startup diagnostic's cashout-residual recipient accuracy
has an equal-history mean of 10.273%. Startup falls outside the frozen primary
comparison family. This is retained descriptive exposure, not a qualifying
primary breach or a reason to erase startup payments from the report.

The three attacks extend a fixed policy-aware prior:

- `cashout_residual`: infer possible receipts from later public payouts and
  known co-input values.
- `split_balance`: match known same-owner input values to possible payment and
  change values, using chronology, anchors and disclosed spentness.
- `tag_split`: restrict that split reasoning to attacker-authored receipts sent
  to honest users.

These are exhaustive joins within their declared local rules. They do not solve
the complete hidden spending history, enforce the full greedy selector in every
hypothesis, or recycle guessed matches into known facts. A guessed numerical
match is not a proof that the proposed payment caused the cashout.

## Measured guessing rates

Each cell below is correct / eligible, with pooled payment rates in parentheses.
These counts describe the batch; inference uses equally weighted independent
histories, not 968 independent payments.

| Variant | Sender | Recipient | Both parties | Amount within 10% | Exact amount |
| --- | --- | --- | --- | --- | --- |
| Prior | 31/968 (3.20%) | 52/968 (5.37%) | 0/968 | 37/968 (3.82%) | 0/968 |
| Cashout residual | 32/968 (3.31%) | 44/968 (4.55%) | 1/968 (0.10%) | 34/968 (3.51%) | 0/968 |
| Split balance | 36/968 (3.72%) | 55/968 (5.68%) | 3/968 (0.31%) | 42/968 (4.34%) | 1/968 (0.10%) |
| Tag split | 36/968 (3.72%) | 55/968 (5.68%) | 3/968 (0.31%) | 41/968 (4.24%) | 1/968 (0.10%) |

For split balance, equal-history mean rates are 3.705% sender, 5.631% recipient
and 4.290% amount within 10%. Paired advantages over the prior are 0.477, 0.313
and 0.513 percentage points respectively. These are small observed differences,
not established improvements or bounds on a stronger attack.

The split and tag variants each make one correct exact-amount guess. Neither
issues a uniqueness certificate, so these hits do not establish a logically
forced disclosure. Equally, this screen cannot establish that there are zero
forced disclosures: it did not perform that search.

| Regime and variant | Sender | Recipient | Amount within 10% | Exact amount |
| --- | --- | --- | --- | --- |
| Overlap: prior | 18/486 | 33/486 | 18/486 | 0/486 |
| Overlap: cashout residual | 19/486 | 16/486 | 18/486 | 0/486 |
| Overlap: split balance | 18/486 | 35/486 | 17/486 | 0/486 |
| Overlap: tag split | 18/486 | 35/486 | 17/486 | 0/486 |
| Sparse: prior | 13/482 | 19/482 | 19/482 | 0/482 |
| Sparse: cashout residual | 13/482 | 28/482 | 16/482 | 0/482 |
| Sparse: split balance | 18/482 | 20/482 | 25/482 | 1/482 |
| Sparse: tag split | 18/482 | 20/482 | 24/482 | 1/482 |

No regime was selected or removed after seeing its outcome. The sparse variant
adds time gaps; it does not establish a smaller active owner population or test
arbitrary real-world low activity.

Selective relationship precision also stays low. Selection uses the frozen
ranking and `ceil(q*N)` independently within each history. Thus the actual
selected counts differ from exactly 5%, 10% or 25% of the pooled population.

| Variant | Nominal 5% | Nominal 10% | Nominal 25% |
| --- | --- | --- | --- |
| Prior | 0/57 | 0/105 | 0/248 |
| Cashout residual | 0/57 | 0/105 | 1/248 |
| Split balance | 0/57 | 1/105 | 1/248 |
| Tag split | 0/57 | 1/105 | 1/248 |

## Uncertainty and limits

The caps remain 10% identity accuracy, 20% amount-within-10% accuracy, five
percentage points advantage over the prior and 50% selective relationship
precision. None of the observed equal-history estimates exceeds its cap across
the full batch or either regime. The frozen simultaneous lower-bound rule
certifies no breach.

That rule has weak detection power here. The prespecified 99 comparisons use
198 Bonferroni-adjusted Hoeffding tails with family alpha 0.05. At sixteen
independent histories the rate radius is approximately **50.88 percentage
points**; paired-difference intervals are wider still. For example, split-balance
sender accuracy has an interval from 0% to approximately 54.58%. Eight-history
regime intervals are even wider. These bounds cannot qualify the adopted
targets, even with low observed rates. They must not be narrowed after seeing
the result or replaced by treating correlated payments as independent samples.

Other limits are substantive, not just sample size:

- Only the pooled final-history view was attacked. Chain-only and individual
  participant records are retained but were not evaluated; earlier horizons
  remain open. More information can change these heuristics' rankings, so the
  pooled result does not substitute for those measurements.
- The prior is one declared algorithm, not the strongest possible behavioral
  posterior. Four scheduled sends per user, high starting capital, uniformly
  selected recipients and retained balances are artificial workload choices.
- Automatic least-excess input selection is a modeled policy. The actual wallet
  accepts caller-selected input positions. Native key separation removes one
  tested alias; independent opaque funding/payout labels do not validate every
  native-byte correlation.
- Actual transaction bytes, proofs, encrypted delivery, RPC/network metadata,
  adaptive interference, independent people and realistic wallet usage were not
  generated here. More samples alone cannot repair those omissions.

The result supports continuing research on persistent balances and testing
specific remaining leaks. It does not establish real-world anonymity,
cryptographic confidentiality or production safety. Earlier prompt-cashout,
legacy key-reuse and H16/H18 failures retain their original conclusions.

## Validation and retained evidence

All 62 frozen control groups passed: 13 model groups with 545 exhaustive
proposition comparisons, 17 workload groups, 22 observer groups and 10 scoring
groups. Every held-out history passed the generating-policy checks, integer
accounting, complete drainage and truth inclusion in both original full CP-SAT
and Z3 encodings. These are fully pinned truth checks; they are not successful
whole-history reconstructions or independent cryptographic verification.

A separate post-run checker recomputed all sixteen histories' eligibility,
field counts and selected rankings, including 1,280 field-counter and 768
selective-counter cells, then recomputed all 99 aggregate intervals. All passed.
It independently rewalked the modeled ledger and rebuilt participant records;
it did not rerun the exact generating-policy validator or the full solvers.
This is an adversarial author-team cross-check, not an external audit. The
[review receipts](evidence/2026-10-21-strong-privacy/review/summary.json) bind the
checker and original scored inputs.

A later development-only boundary check found that floating-point subtraction
can mark an advantage exactly equal to the 5-percentage-point cap as an
exploratory exceedance: `24/60 - 21/60` evaluates slightly above `0.05`, whereas
the exact fraction equals it. This does not affect this batch: the independent
exact recount matched every reported comparison. Certified bounds are unaffected
in that control. Preserve the frozen scorer; future studies should compare
point estimates to caps using exact rational arithmetic.

Protocol code, circuits, native key derivation, parameter identity and security
invariants were unchanged. The new files analyze synthetic ledgers; they do not
authorize payments or release reserve KAS. Modeled ownership, spentness and value
conservation were checked, but no new native replay, reorg, setup, withdrawal,
data-availability or provider-failure evidence follows. Missing inputs/checks
remain incomplete evidence rather than successful privacy outcomes.

The export retains exact approved observer inputs, predictions, seals, aggregate
scores, process/input attestations and frozen source/specification snapshots.
It excludes hidden seeds, full truth and raw logs. Its combined contents are a
research evidence package, not the inputs of a single blinded observer.
`freeze-public.json` explicitly redacts the dependency path; the original freeze
hash remains in the seals. The private attempt and all earlier evidence remain
intact. No funds, broadcasts or new native proofs were used.

**Next research decision:** retain this result unchanged. Before a qualification
run, finish the declared views/horizons, challenge the prior and workload with
realistic heterogeneity and native-surface evidence, and prospectively choose
enough independent histories for the unchanged caps and comparison family.
Do not turn this small screen into a milestone-3 clearance.
