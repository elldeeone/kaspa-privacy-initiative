# Reconstruction with known wallet behavior — H15

Offline follow-up to H14 on `shared-pool-four-wallet`. The assumptions were
committed as `7bf197f` before the new observer ran. All eight public transcripts
are byte-identical to H14; the economic workloads remain frozen at `1bf14d0`.

**Result: fresh proofs survive the frozen stronger-observer screen.** Fresh exits
retain multiple payment-source sets for five or six of six payments in every
case, and more alternatives than saved exits in all four pairs. This strengthens
the evidence for fresh normal authorizations while leaving strong privacy open.

| After complete drainage, primary wallet profile | Saved exits | Fresh proofs |
| --- | ---: | ---: |
| Payment sources uniquely identified | 2/24 | 2/24 |
| Payment source guesses correct | 4/24 | 2/24 |
| Partial-withdrawal sources uniquely identified | 0/8 | 0/8 |
| Full-exit sources uniquely identified | 20/28 | 0/28 |
| Exact full-exit input notes uniquely identified | 8/28 | 0/28 |
| Full-exit source guesses correct | 28/28 | 8/28 |
| Source candidates per full exit | 1–6 | 9–10 |

All singleton inferences are correct under the tested profile. A correct recency
guess is a separate measure from a uniquely forced link. These identify source
transactions or note positions, not people, and are not anonymity percentages.

The two unique payment links are still the early payments before another
depositor arrived. No additional payment becomes unique during drainage.
Four fresh-policy payment targets lose some alternatives during drainage;
twenty saved-policy targets do. No private payment has a uniquely identified
real-input position set. All actual input/source sets survive every observation.

| Case | Ambiguous fresh payments | Ambiguous saved payments | Sum of fresh payment source-set counts | Saved |
| --- | ---: | ---: | ---: | ---: |
| a0-s0 | 5/6 | 5/6 | 155 | 73 |
| a0-s1 | 6/6 | 6/6 | 206 | 112 |
| a1-s0 | 5/6 | 5/6 | 155 | 74 |
| a1-s1 | 6/6 | 6/6 | 206 | 116 |

These sums evaluate the frozen screen; they do not count joint histories.

**What changed from H14:** knowing the transaction shape reduces fresh-exit
source alternatives from 77–78 source combinations to 9–10 single-source
possibilities. For saved exits, shape knowledge alone still leaves only 4/28
uniquely linked sources. Adding the receipt-anchor rule raises that to **20/28**.
It also reduces saved-policy payment alternatives from a total of 676 in H14,
to 548 with shape knowledge, to 375 with receipt-anchor knowledge. Fresh payment
alternatives fall from 746 to 722. Receipt knowledge adds nothing to the fresh
arms because their exit anchors are current; both profiles agree exactly there.

**Decision:** retain fresh normal authorizations with private saved fallbacks.
Do not use saved proofs as the normal privacy path. The current assumptions
survive this screen, but slot/amount knowledge removes much of H14's withdrawal
ambiguity. Stage 2 remains open. A useful next narrow test is one participant
sharing only their own activity with the observer, scoring relationships that
do not involve that participant. That would test useful privacy against someone
inside the pool. It is a proposed follow-up, not an executed experiment or a
new protocol decision.

[Results](evidence/2026-10-20-wallet-policy-reconstruction/summary.json),
[all attack metrics](evidence/2026-10-20-wallet-policy-reconstruction/aggregates.json),
[drainage progression](evidence/2026-10-20-wallet-policy-reconstruction/retroactive.json).

## What the observer learns from the client

The primary `wallet` profile knows four construction defaults:

1. Admission puts the net deposit in the first note and zero in the second.
2. Partial withdrawal puts any retained private value in the first note and
   zero in the second.
3. A full exit spends exactly one positive note.
4. Saved exit proofs are made at receipt. An older-than-current exit anchor
   therefore identifies the note's creation batch. A current anchor can
   authorize an older note using a fresh proof.

For example, an 11 tKAS deposit with the fixed 0.4 fee creates a first note worth
10.6 tKAS under this profile. A full exit spends a note worth its public payout
plus the fee. The hiding cryptography does not conceal these consequences of
known construction rules. The remaining question is which earlier note was
spent and which earlier transactions it links.

The `shape` ablation uses rules 1–3. Comparing it with `wallet` isolates the
additional receipt-anchor assumption. The stored H14 `protocol` results remain
the baseline. The observer receives no fresh/saved arm label; it applies the
same rule to every transcript.

This is a profile of scripted prototype construction. There is no automatic
coin selector to reverse engineer. Normal payments and partial withdrawals still
allow one or two inputs; normal payment output values and dummy flags are
unknown. Private plan choices, wallet identities, intended recipients and which
output belongs to which account are not supplied. Funding-key-to-shielded-account
attribution is not modeled. Additional justified account/ownership information
could narrow candidates further. These results do not cover all possible
knowledge of a deployed wallet.

## Method and checks

Four ledgers, each with fresh and saved exits, run under both profiles:
sixteen new observations. Each ledger has six private payments, two partial
withdrawals and seven full exits, with interleaved independent deposits.
All are observed through terminal zero reserve. This changes the observer's
knowledge, not any payment, amount, fee, order, identifier or destination.

Every spend is evaluated on appearance and after complete drainage. Each of
the six payment targets is also revisited after every full exit. This preserves
H14's 67 joint observation points per transcript: 1,072 across the new runs.
Candidate sets must nest as wallet ⊆ shape ⊆ protocol, and all actual input and
source sets must remain feasible. The fixed recency ranking is unchanged.

The inherited integer conservation relation receives explicit policy constraints
in two separately encoded solvers. Exact rational graph search accepts a
candidate only after integer CP-SAT validates the whole selected graph.
Independent exhaustive small ledgers check the encodings and hybrid engine.
Sixteen controls pass, including the original H14 tests, fixed padding, one-note
exit rejection, current-root symmetry, stale-root assumptions and prefix
information boundaries. A deliberately nonconforming wallet trace is valid
under the protocol relation and rejected under the assumed profile. This
distinguishes client attribution from consensus facts.

Filesystem/network sandboxes mount only public inputs, observer code and solver
libraries. The controller opens hidden truth after predictions are written.
No workload manifest, generator, wallet key or unused fallback is mounted.
Access probes, code hashes, candidate sets and separate scores are retained.
The researcher and a reader given the public recipe are not blinded.

## Costs and inherited mechanics

Actual funds spent: **zero**. New private proofs: **zero**. Circuit, covenant,
parameters and H14 calibration are unchanged. H14's genuine four-wallet exits
and saved-proof preservation are inherited evidence, not newly tested here.
Native fee cost remains 7.6 hypothetical tKAS per nineteen-operation branch,
excluding funding/setup. The synthetic ten-minute event schedule and waits
also remain unchanged.

The complete sixteen-observation run, including controls, took **9 minutes
17.01 seconds** with four workers. Individual observations took 19.703–277.886
seconds. GNU time reported a maximum RSS of 157,680 KiB (about 154 MiB); this is
a process high-water mark, not combined concurrent memory usage. These are
observer costs, not proving costs. All sixteen observations completed on the
first full run; no workload was replaced or redrawn. The additional GNU-time
measurement is retained separately as
[resources.json](evidence/2026-10-20-wallet-policy-reconstruction/resources.json).

See the [frozen scope](WALLET-POLICY-PRIVACY-SPEC.md),
[adversarial review](WALLET-POLICY-PRIVACY-REVIEW.md), and
[H14 native calibration](TWO-INPUT-RECONSTRUCTION.md).

## Reproduction and boundaries

Using the pinned environment from `privacy-study-requirements.txt`, from this
directory:

```sh
python3 wallet-policy-privacy.py prepare "$KPI_H15_PRIVATE" "$KPI_H14_ORIGINAL"
python3 wallet-policy-privacy.py run "$KPI_H15_PRIVATE" --workers 4
python3 wallet-policy-privacy.py export "$KPI_H15_PRIVATE" "$KPI_H15_EXPORT"
```

Choose fresh output directories. `KPI_H14_ORIGINAL` is the retained H14 private
execution directory containing its original public traces and separate truth.
The prepare step copies those exact inputs; it does not generate new cases.
Run includes all sixteen control tests before observation. Published files are
allowlisted; private truth and provenance paths stay outside Git.

The results depend on correct identification of the client profile and the
existing hiding assumptions. Surviving alternatives are not equally probable,
independent users or a real-world anonymity estimate. Four simulated funding
sources do not prove four people; one common public funder gives one funding
cluster. RPC/IP observation, realistic timing, cryptographic attacks and external
identity knowledge are outside this study. A failed or unknown solver outcome
would be inconclusive, not additional ambiguity.
