# 32-role/eight-adversary privacy test

Date: 2026-10-20. Candidate: `aa6ed4947f7c25db128cd5d89b7c021d6b8fe690`.

**Status: bounded attack results; privacy gate incomplete.** The deterministic
cashout-matching batch completed all eight histories. Immediate receipt cashout
revealed 99/99 primary payment amounts exactly to the total-cashout heuristic.
For persistent balances, the best of three fixed amount attacks guessed 5/99
within 10%, with zero exact matches. The constant-amount baseline scored 3/99.
These are finite attack measurements on four independent request sets, not a
privacy pass. The local exact-disclosure relaxation also completed all eight
histories, with no forced undisclosed facts. Its weaker scope cannot establish
full-model ambiguity or useful privacy.

Three full-history CP-SAT formulations produced no initial feasible assignment
or prediction. The compact-index and monetary-flow variants were stopped after
approximately eight hours each; the separate original Z3 probe exhausted memory.
These are failed computations, not privacy evidence.
Milestone 3 remains behind the early privacy gate.

The original Z3 encoding repeats large prefix-reserve expressions. Static
inspection counted 907,395 selector occurrences inside those expressions for
the first public history. Factoring or removing entailed cuts is a possible
performance experiment, not an established fix. The fundamental search also
jointly assigns note values, ownership, input selection and cashout pairings.
No new full-history variant is needed before the practical tests below can run.

## What is being tested

Can public amounts, wallet ownership rules, eight colluding participants' records
and later cashouts uniquely reveal an otherwise undisclosed internal payment's
sender, recipient or exact amount? This is a failure-seeking first stage of
[RFC-0014](../../docs/rfc/0014-owner-aware-privacy-evaluation.md), using the
[frozen specification](POPULATION-PRIVACY-SPEC.md).

The [source review](../../research/shielded-kas-32-role-evaluation-2026-10-20.md)
and [native-byte calibration](EARLY-PRIVACY.md) informed the model. The earlier
ownerless amount model cannot establish user anonymity, and the historical
H15/H16 single-input exit rule does not match the current wallet.

Four independently generated request sets each have two matched histories:
persistent balances and immediate cashout of receipts. Two sets overlap in time;
two include a modeled sparse interval. Each history has 32 wallet roles, eight
under common adversarial control, interleaved admissions, two payments per role,
active amount tags, private change and complete final drainage.

This gives eight histories with 64 ordinary payments each, but only **four
independent request sets**. It is not a powered guessing-rate study. Primary
targets are honest-to-honest payments made after all 32 roles have joined.
Startup and counterparty facts stay in separate diagnostic strata.

## Implementation checks and initial execution

The specification, executable sources, solver dependency bytes and earlier
calibration identity were frozen before sampling hidden seeds. Freeze SHA-256:
`a0f7655c64f0702277f708fc6c647e75a534edceb9574f9c4260e4eaeb6645c6`.

The isolated control run passed 13 model controls and 13 workload controls.
The model controls include 545 exact proposition comparisons with independently
enumerated tiny owner/value/spend histories. They cover common ownership,
two-input exits, payment/change ordering, participant knowledge, prefix isolation,
repeated commitments, contaminated schemas, forced and ambiguous cases, and a
32-role sparse linked-payout control with an unlinked comparison.
Separate development checks also matched four participant views and twelve
prefixes between generator and model; concrete truth satisfied both encodings.
These checks validate tested implementation behavior, not cryptographic security.

All eight held-out histories generated without skipped requests, resampling or
added funding. Their modeled reserve balances reconcile to zero after paying
every claim and pool fee:

| Request set | Activity | Persistent operations | Prompt operations |
| --- | --- | ---: | ---: |
| 1 | Overlap | 150 | 192 |
| 2 | Overlap | 155 | 192 |
| 3 | Sparse | 152 | 192 |
| 4 | Sparse | 152 | 192 |

Actual modeled capital, payment-value and operation shares are retained in
`generation.json`; eight of 32 roles does not imply 25% of every resource.
Funding and exit accounting here is generated integer arithmetic, not newly
verified native transactions or evidence of chain acceptance.

Each run gives the observer only one arm's public file and the pooled
records of roles 0–7. The observer cannot access the other matched arm, private
seeds, generated truth, other views, the home directory or an external network.
Pooled participant knowledge and active-participant knowledge coincide under
this declared nonadaptive attack; they are not counted as independent samples.

Each claimed forced fact needs a satisfying assignment for its value and an
unsatisfiable alternative in both CP-SAT and integer Z3. Predictions must be
sealed before a separate scorer receives the pinned private truth. That scorer
requires the actual generated history to satisfy both models before interpreting
any disclosure. A second review found no pre-run blocker in the model, workload
or runner; it was an author-team review, not an independent security audit.

## Modeled public surface and native correspondence

| Modeled observation | Native/current-wallet basis | Boundary |
| --- | --- | --- |
| Initial reserve and funding identity | Public descriptor and selected funding output | Funding-to-role association is hypothetical side information. |
| Mode, fee, deposit, payout and reserve successor | Public authorization and native input/output values | Integer accounting is modeled; no new proof or native execution. |
| Ordered commitment positions and historical count | Append-only commitment state and authorization anchor | Opaque labels preserve equality; they are not generated cryptographic commitments. |
| Recipient output 0, sender change output 1 | Current wallet PAY construction | A client-policy assumption, not an anonymity guarantee of the proof relation. |
| One/two selected inputs with a common owner | Current wallet's owned-note selection and EXIT | Input positions stay hidden except in disclosed author records. |
| Positive recipient receipts and authored records | Own-key scanning and caller-selected actions | Receipt alone grants neither another sender's inputs nor sibling plaintext. |
| Ordered times and public destinations | Public chronology and native payout scripts | Modeled minute slots and opaque destinations; no native key/script equality test. |

The [calibration decoder](early_privacy_surface.py) and
[wallet source](src/two_input/wallet.rs) provide the native correspondence.
Proof bytes, ciphertext bytes, nullifier/tree witnesses, signatures, real native
scripts, infrastructure observations and real time are not synthesized here.
Their complete current-version qualification remains separate. In particular,
funding/exit derivation namespace reuse is absent from this population model;
opaque modeled destinations do not establish its absence in the wallet. A
[subsequent seven-proof native diagnostic](ADDRESS-REUSE.md) confirms the collision
and conditional internal disclosure in a separate two-funded-wallet history.
It does not change the frozen population model or qualify its 32-role claim.

## Local disclosure result

[Method 04](POPULATION-PRIVACY-METHOD-04.md) retains the complete public record
but removes undisclosed input equations outside the target, bootstrap, disclosed
authors and three subsequent cashouts. Its 12 new controls passed alongside the
original 26 controls. Fifty exhaustive full-history witnesses fit both slice
encodings; the controls deliberately exhibit a slice alternative impossible in
the full model. Two source reviews found no blocker; these are author-team
reviews, not an independent security audit.

All eight runs completed all 64 ordinary targets each. Primary counts were
28, 23, 24 and 24 per arm: 99 persistent and 99 prompt payments. None had a
forced, undisclosed sender, recipient or amount in this relaxation; no
undisclosed forced facts appeared in the diagnostic strata either. Each
prediction file was sealed before its scorer checked concrete generated truth
in both original full models. The first run's prediction SHA-256 is
`61409119db97a133a90b9181d4ddd7266d75b5d44258e57809a0cad962189405`;
all case seals and scores are preserved in the public evidence. Completion here
covers this local relaxation, pooled records and final horizon only.

The slice also finds no forced undisclosed fact in the prompt-cashout
histories, while the deterministic matching attack below recovers all 99 primary
amounts exactly. This is a limitation of the relaxation: it permits histories
outside the workload's timing and spending policy. A plausible alternative in
that enlarged set can be impossible in the full model and has no probability
weight. It is not evidence that a realistic guess is unlikely to succeed.

## Limits and continuation

The bounded local result is not a privacy qualification. The model permits some
histories outside the generator's scheduling, recipient-admission, amount-prior
and automatic input-selection policies. A forced fact in this relaxation may be
a valid conditional counterexample; alternatives in it do not establish privacy.

No supported primary persistent-arm forced counterexample emerged from the
completed local searches. The whole-history reconstruction remains incomplete;
public-only/separate views, earlier horizons, stronger attacks and powered
statistical qualification also remain open. Any later forced finding still
requires pinned-truth validation and review under the frozen stopping rule.
Prompt-cashout and startup results cannot silently fail the mature
persistent-payment claim.
All RFC-0012 targets are unchanged. No real-world anonymity follows from this
synthetic study, and no funds, new proofs or broadcasts were used.

## Completed cashout-guessing measurement

[Method 05](POPULATION-PRIVACY-METHOD-05.md) preregistered three deterministic
guesses on the already-generated histories: the first eligible later cashout's
total input, half that total, and a residual after subtracting a known tagged
note. These are guesses, not proofs that either note was consumed. The original
26 controls and seven new controls passed before inference. All eight prediction
files and a batch manifest were sealed before the first private scorer ran.
Every score passed original full-model CP-SAT/Z3 truth inclusion and independent
integer accounting. A second author-team review recomputed every counter from
the exported scored rows and found agreement.

There are 64 ordinary targets per history, 512 predictions across the paired
arms. Primary eligible counts are 28, 23, 24 and 24 in each arm: 99 payments
per arm, but **four independent request sets**, not 198 independent samples.
The pooled final-history view excludes directly known facts and excludes any
adversarial endpoint from the primary stratum.

| Fixed variant | Persistent amount within 10% | Prompt amount within 10% | Persistent recipient | Prompt recipient |
| --- | ---: | ---: | ---: | ---: |
| Constant amount / public-hash role baseline | 3/99 | 3/99 | 6/99 | 6/99 |
| First eligible cashout total | 4/99 | 99/99 | 6/99 | 6/99 |
| First eligible cashout half | 0/99 | 0/99 | 6/99 | 6/99 |
| Known-note residual | 5/99 | 3/99 | 4/99 | 4/99 |

All persistent-arm exact-amount counts are zero. The prompt total-cashout attack
recovers all 99 primary amounts exactly; the other prompt exact counts are zero.
The residual rule's recipient guesses do not outperform this limited role
baseline. Sender predictions are only the baseline: 1/99 persistent and 2/99
prompt. They are not a sender-attack evaluation or evidence of sender privacy.

| Request set | Regime | Primary per arm | Persistent baseline amount | Persistent total | Persistent half | Persistent residual | Prompt total |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | Overlap | 28 | 2 | 0 | 0 | 1 | 28 |
| 2 | Overlap | 23 | 0 | 0 | 0 | 0 | 23 |
| 3 | Sparse | 24 | 0 | 3 | 0 | 2 | 24 |
| 4 | Sparse | 24 | 1 | 1 | 0 | 2 | 24 |

The final five columns are correct within-10% amount guesses, with the row's
primary denominator. Every attack predicts every target; no per-payment best
guess is selected using truth. The baseline is deliberately limited and omits
strong scheduling, conditional-recipient and behavioral priors. Low rates do
not qualify the adopted thresholds. Other diagnostic strata, exact-match counts
and all individual correctness flags remain in the exported score artifacts.

**Interpretation:** the expected immediate-cashout exposure is reproduced, and
these three simple attacks perform poorly against the persistent histories.
That supports continuing research on persistent spending, without claiming it
meets the intended privacy level. Native script/address equality, stronger
behavioral and active attacks, selective disclosure, public-only/separate views,
earlier horizons and powered statistical qualification remain open. Further
practical privacy measurements need not wait for whole-history reconstruction.

## Reproduction and retained state

The local attempt is `/tmp/kpi-32-role-20261020-method-01`. Its private directory
contains seeds and truth and must stay outside Git. Preserve it and every
stopped attempt; do not rerun generation or reuse an existing run directory.
The [public checkpoint](evidence/2026-10-20-population-privacy/README.md) contains
the freeze, controls, generation summary and first observer inputs, with hashes.

Subsequent attempts preserve the same histories and declared observer inputs:
[method 02](POPULATION-PRIVACY-METHOD-02.md) changes input-selection encoding;
[method 03](POPULATION-PRIVACY-METHOD-03.md) adds entailed monetary-flow equations.
Neither changes the feasible history set or any privacy threshold. Their
pre-run controls and interrupted progress logs are retained separately.
[Method 04](POPULATION-PRIVACY-METHOD-04.md) explicitly removes some hidden
input equations: it can find a forced disclosure but cannot establish full-model
ambiguity or pass the privacy gate. Its predictions must still be sealed before
the scorer checks actual truth in both original full models.

For a new attempt, using the pinned dependency environment:

```sh
python population_privacy_trial.py prepare /tmp/a-fresh-attempt
python population_privacy_trial.py controls /tmp/a-fresh-attempt
python population_privacy_trial.py generate /tmp/a-fresh-attempt
python population_privacy_trial.py run /tmp/a-fresh-attempt
```

The runner defaults to the first persistent history, pooled records, final
horizon. It supports other final-history views with `--case` and `--view`.
Earlier-horizon queries are supported by the model but are not scheduled by
this first runner. Missing views/horizons remain incomplete, never a pass.

Completed follow-ups reuse the existing frozen histories instead of generating
new ones. For a fresh method-05 replay directory with the preserved private
parent attempt available:

```sh
python population_privacy_heuristic_trial.py prepare /tmp/a-fresh-replay --source /tmp/kpi-32-role-20261020-method-01
python population_privacy_heuristic_trial.py controls /tmp/a-fresh-replay
python population_privacy_heuristic_trial.py run_all /tmp/a-fresh-replay
```

The exported public evidence is sufficient to repeat observer inference. Private
seeds and full truth are deliberately absent; the separate scored evidence and
their commitments are retained without making private histories public.
