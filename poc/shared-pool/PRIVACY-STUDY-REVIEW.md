# H11 adversarial second-pass review

Self-review by the implementing agent, not an independent security audit.
[Frozen scope](PRIVACY-STUDY-SPEC.md), [result](PRIVACY-STUDY.md).

| Concern | Check and remaining boundary |
| --- | --- |
| Inflation / wrong reserve release | No circuit/covenant/native-validator changes. Genuine proofs and exact public backing reconcile four complete alternate drains. The model also rejects a balanced total whose payout cannot belong to any individual funding tree. Passing checks do not establish cryptographic soundness. |
| Two spends / stale state | The model uses distinct input choices; the native builder rejects the losing same-nullifier bundle against each winner's successor. H10 supplies hostile duplicate-witness native checks. Explicit synthetic contexts do not establish actual UTXO freshness, reorg handling or live finality. |
| Unauthorized exit | Old/fresh proof pairs bind the same domain, nullifier, recipient, value and fee. Only historical anchor fields may differ; proof bytes are genuinely regenerated. Exit processes have selected bundles/public state, no keys or PK. This is same-host process isolation, not hostile-host protection. |
| Confidential material / observer contamination | Observer mounts contain only their public arm, runtime and attack code; no generator, seed file, truth, home or network. Scorer runs separately. Export allowlists omit native old arms/pending capabilities and scan actual secret/unused-proof bytes. Published synthetic seeds are not secret against an experiment-aware observer. |
| Funding and owner inference | A funding ancestor is a transaction, not a person. Four signing wallets or funding roots are not four independent users. Shared ancestry is reported separately and does not prove common ownership. |
| Model overclaim | Fresh native bytes are decoded independently and match two model cases. The population study assumes cryptographic confidentiality and excludes stronger byte-level, wallet-specific, RPC/network and external-data attacks. Native calibration is not population validation. |
| Selective reporting | Spec committed before generation. Both primary regimes retain every frozen ledger and withdrawal through complete drain. Equal-amount and singleton controls stay separate. Statistical resampling uses whole paired ledgers; it does not multiply sample size by notes, arms or horizons. Thresholds were not changed. |
| False ambiguity / numeric errors | Integer sompi throughout. Unknown/invalid solver status is an error. CP-SAT rejects unsupported intermediate ranges rather than overflowing. Exhaustive tiny fixtures, a Z3 comparison and 45 CP-SAT comparisons check candidate sets; independent score checks require true notes/sources/ancestors to remain feasible. |
| Dependency disappearance | A saved authorization remains the no-prover exit path under retained authenticated history/current-chain assumptions. Fresh proofs need private keys, public parameters and proving resources. Neither policy repairs loss of all history or fee repricing. |

## Why the specialized flow calculation preserves the relation

It applies only when all observed exits follow the growth phase and use the
latest commitment count. Otherwise the general model handles the trace.
The code enumerates every transfer input-source choice among eligible unspent
notes. Two outputs from the same creation have symmetric eligibility and value
constraints; enumerating one representative when both survive removes only
their label permutation. Reported marginal note candidates expand the pair.

With one input per transfer and no aggregation, each live note belongs to exactly
one funding tree. Each split deducts its public fee from that tree's budget.
For a fixed topology and an assignment of observed full exits to its leaves,
feasibility is equivalent to two checks: no more exits than leaves, and enough
remaining integer value for every unwithdrawn leaf's floor. If no leaves remain,
the budget must equal the observed input values exactly. When leaves remain,
assign the floor to all but one and give the residual integer value to the last;
internal values are then sums of descendant leaves and fees. Every internal
note exceeds its floor and is bounded by its funding amount. Thus the reduction
has both a necessary and a constructive sufficient direction.

The latest-root condition makes every current leaf eligible for every observed
exit; root-assignment partitions plus leaf capacities supply a distinct-leaf
matching. The general model is required if anchor restrictions or later growth
invalidate that simplification. Candidate sets are unions of complete feasible
histories, not independent guesses that may spend the same note twice.

## Operational corrections

Generic integer solving was slow for several four-payment partial-drain queries.
We retained those attempts, changed only the exact solving strategy and reran
all identical frozen ledgers. No hard result was discarded, converted to
"unknown anonymity", replaced with a new seed or used to revise the target.
The final native preparation is reused unchanged: only the observer calculation
changed. Native/old-world evidence and all sensitive capabilities stay private.

The passed screening target is reported as passed. High residual funding-origin
inference is a separate measured limitation, not a retroactively introduced
failure criterion. Equal **net** deposits are a subsequent hypothesis, not an
unreported extra policy or claimed remedy in H11.
