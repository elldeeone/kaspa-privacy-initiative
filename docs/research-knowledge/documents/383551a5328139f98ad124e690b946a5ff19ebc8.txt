# Blinded two-input reconstruction — H14

Frozen specification: [`1bf14d0`](TWO-INPUT-PRIVACY-SPEC.md), following H13 at
`4630617`. Branch: `shared-pool-four-wallet`. Offline only; no funds spent.

**Result: the frozen modest screen passed; strong privacy remains unestablished.**
Fresh exits preserve five or six ambiguous payment-source combinations out of
six in every case. They increase the number of source alternatives in two of
the four cases. They do **not** reduce uniquely identifiable payment links in
this workload: **2/24 in both policies**, both early payments before another
depositor arrived. No additional payment became uniquely identifiable on drain.

| After complete drainage | Saved exits | Fresh exits |
| --- | ---: | ---: |
| Private-payment source sets uniquely identified | 2/24 | 2/24 |
| Private-payment sources guessed correctly by fixed recency ranking | 2/24 | 2/24 |
| Partial-withdrawal source sets uniquely identified | 0/8 | 0/8 |
| Full-exit sources guessed correctly by fixed recency ranking | 28/28 | 8/28 |
| Full-exit source sets uniquely identified | 4/28 | 0/28 |

These distinguish **a correct guess** from **a logically forced link**. Saved
anchors make the latest eligible source a very effective guess in this recipe,
even where other histories remain possible. Fresh full exits retain 77–78
possible source-transaction sets, versus 1–66 for saved exits. Those are sets of
one or two transaction labels, not people or equally likely histories. Neither
22/24 ambiguous payments nor 20/28 incorrect exit guesses is a privacy percentage.

| Frozen case | Ambiguous payments: fresh | Saved | Sum of per-payment source-set counts: fresh | Saved |
| --- | ---: | ---: | ---: | ---: |
| a0-s0 | 5/6 | 5/6 | 161 | 126 |
| a0-s1 | 6/6 | 6/6 | 212 | 212 |
| a1-s0 | 5/6 | 5/6 | 161 | 126 |
| a1-s1 | 6/6 | 6/6 | 212 | 212 |

The sums implement the frozen comparative screen; they are not counts of joint
histories. Ten payments lose source alternatives during drainage with saved
exits; none lose source alternatives with fresh exits. Private inputs remain
non-unique for all 24 payments, including the two with a unique source transaction.
All true input/source sets survive every reported attack and observation point.

**Decision:** retain fresh normal-path authorizations and private saved exits.
The clearest measured benefit is withdrawal linkability. Payment-source ambiguity
survives this small protocol-only observer, but public wallet behavior could
narrow it further. The next privacy question is to give the observer the wallet's
known one-note exit and deposit-padding rules on these same workloads, before
expanding wallet features. That follow-up has not been run. Stage 2 remains open.

[Public results and calibration](evidence/2026-10-20-two-input-reconstruction/summary.json),
[aggregate attacks](evidence/2026-10-20-two-input-reconstruction/aggregates.json),
[retroactive narrowing](evidence/2026-10-20-two-input-reconstruction/retroactive.json).


## What was tested

Two amount rows crossed with two deposit/drain schedules, each run with fresh
and saved exits: **four paired ledgers, eight observations**. Each ledger has
four deposits, six private payments, two partial withdrawals with change, and
seven final exits. Receipts from different depositors are merged. Deposits
arrive between payments; there is no background traffic. The full economic
workloads were committed before generation or scoring. Their amounts, order,
fees and decision threshold were not changed after results.

The process is blinded to wallet labels, note values, input positions and the
manifest. It receives public order, anchor counts, modes, output positions,
deposits, payouts, fees, balances and public labels. It assumes confidentiality
of the cryptographic bytes. Source combinations are sets of transactions that
created a spend's real inputs. They are not people, deposit ancestry, equally
likely histories, or a probability of privacy.

The fresh and saved arms have identical payments, partial withdrawals and
payouts. Only the final exit authorizations differ. Fresh exits use the latest
commitment root; saved exits use the root at receipt. Unused saved capabilities
are private. Both one- and two-note explanations are allowed for every spend,
including exits. Zero notes and slot permutations are not counted as alternatives.

## Controls and exact inference

The observer is isolated with public input and code only; its output is written
before truth is opened by the scorer. The published synthetic recipe can reveal
the intended history to a reader given that extra material; this blinding applies
to the observer process, not to a human with the complete repository. It ranks candidates with a fixed
recency rule and never selects an attack based on private correctness. The amount
baseline uses public upper bounds, while the joint model uses shared integer
note values, at-most-once consumption, anchors, floors, fees and conservation.
Full drainage forces every positive note to have been consumed.

Seven incomplete observer batches are retained: direct CP-SAT, pure integer SMT,
and refinements of the exact hybrid search. The final version avoids repeated
horizon work, encodes fixed selections directly for integer presolve, and asks
about singleton inputs before pairs. Backward value bounds, sibling-output
bounds and explicit reserve identities follow from the existing conservation
equations and anchors. These change computation, not economic assumptions,
candidate enumeration or the final recency ranking. Completed earlier candidate
sets agree exactly at all 603 comparable required observation points. The final
engine searches candidate graphs using exact rational arithmetic, then validates every positive graph against the original
integer CP-SAT model. A rejected graph is blocked and search continues. Rational
infeasibility proves integer infeasibility; rational feasibility alone never
counts as a result. No floating-point money or amount rounding is used.

To avoid repeating the same search, observation points are computed from the
end backwards. A valid complete history supplies a valid earlier prefix. Other
candidates are queried against only that prefix, so the reported information
sets and ranking do not change. Independent fresh-prefix controls check this.

Eight control tests cover independent exhaustive enumeration, two independent
integer encodings and the final engine; single-source and symmetric fixtures;
zero-note spending, replay, impossible conservation and anchors; input typing;
public-decoder mutations; and equivalence of observation orders. The decoder
also reads H13's existing thirteen TN10 transactions. It is not a cryptographic
verifier. The Rust harness separately verifies actual proofs and native scripts.
See the [adversarial review](TWO-INPUT-RECONSTRUCTION-REVIEW.md).

## Genuine proof calibration and cost

The first ledger was executed with **26 genuine v6 proofs**: twelve common
operations, seven saved exits and seven fresh exits. Both nineteen-operation
branches passed native consensus/policy checks with synthetic UTXOs. Seven
separate exit adapters per branch received only public state and their bundle;
they had no wallet keys, proving key, host home directory or network access.
All four wallets received final payouts in both branches. Old proofs were
unchanged. Both winner orders rejected the alternative and replay during
current-spentness rebuilding, and both reserves reached zero. The public bytes of each branch decode to
exactly its planned observation, after relabelling only opaque identifiers.
Both exported-body replays independently verify nineteen proofs/native
transactions, and invalid-proof, backing and lineage controls are rejected.
The other three economic ledgers are **models, not genuine proof executions**.

| Measurement | First ledger, both policies |
| --- | ---: |
| Deposited native value | 56 synthetic tKAS |
| Paid out, including partial withdrawals | 48.4 synthetic tKAS |
| Fee per operation | 0.4 synthetic tKAS |
| Fees per nineteen-operation branch | 7.6 synthetic tKAS |
| Additional native fee for fresh exits | 0 |
| Additional fresh proof work | Seven proofs, 150.232 seconds total |
| Warm proof time, all 26 proofs | 21.020–21.988 seconds |
| Cold parameter load | 203.054 seconds |
| Complete native calibration | 764.372 seconds |
| Peak proof-process memory | 6,803,256 KiB, about 6.49 GiB |
| Native mining mass | 330,497–331,628 |
| Actual funds spent | 0 |

CPU proving used four Rayon threads and the existing H13 parameters/VK; the
circuit/covenant and pinned Rusty Kaspa validator were unchanged. Calibration
pins record the original driver; the final binary adds the public trace replayer,
whose hash is recorded in `public-replay-check.json`. These are
local measurements, not current network fee quotations. Fees omit ordinary
funding/setup transactions and congestion. Observation times use one event per
ten minutes: note-to-final-exit waits range from 10 to 180 **simulated** minutes.
That waiting schedule is identical within each pair. It is not a measured
privacy delay or a recommended wallet policy.

## Boundaries and reproduction

This is a small necessary screen for continuing research. It does not close
Stage 2's strong-privacy gate. H11's single-input/deposit-origin scores are
not directly comparable with these merged-source combination metrics. Four
simulated unrelated funding sources do not prove four independent users; collapsing the funding into one public cluster
leaves one cluster. Timing behavior, address reuse, known wallet input/output policies, external
knowledge and RPC/network observation may improve inference. Alternatives are
protocol-valid histories under the declared model; the observer is not told the
test generator's fixed recipient/change layout or deposit-padding policy. Actual live history discovery,
reorgs, contention, fee changes and production cryptographic review were not
retested here. Passing controls does not prove cryptographic correctness.

Install the already pinned packages from `privacy-study-requirements.txt` in
a private environment; the controller's default is
`/home/luke/.local/share/kpi-shared-pool-tools`. From this directory:

```sh
python3 two-input-privacy.py prepare "$KPI_H14_PRIVATE"
/home/luke/.local/share/kpi-shared-pool-tools/bin/python -m unittest two_input_privacy_tests -v
python3 two-input-privacy.py run "$KPI_H14_PRIVATE" --workers 4
RAYON_NUM_THREADS=4 "$KPI_TWO_INPUT_BIN" study "$KPI_H14_PARAMS" \
  "$KPI_H14_PRIVATE/a0-s0/plan.json" "$KPI_H14_PRIVATE/native"
```

Use a fresh private output directory and the existing v6 proving parameters;
never mount the manifest or truth in an observer. The controller verifies the
frozen files against commit `1bf14d0`. A rerun generates new opaque identifiers
and wallet cryptography but the same economic cases. The export includes the
chosen fresh native branch, public projections, candidate sets, scores, isolation
receipts and hashes. Keys, note openings, private truth files and unused saved
exit bodies remain outside Git. The alternate branch is represented by decoded
public fields, hashes and its native-validation summary.

Sources and design assumptions are recorded in the
[frozen specification](TWO-INPUT-PRIVACY-SPEC.md),
[RFC-0011](../../docs/rfc/0011-two-input-private-payments.md),
[H13 native result](TWO-INPUT-TN10.md), and
[existing source review](../../research/compact-policy-study-sources-2026-10-20.md).
ZIP 315's funding/balance/anchor concerns and Orchard's real/dummy distinction
inform the measurement; their security properties are not inherited by v6.
