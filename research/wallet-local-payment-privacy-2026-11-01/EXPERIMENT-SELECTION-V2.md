# Frozen experiment correction: wallet-local practical privacy v2

**Freeze date:** 2026-11-01
**Experiment identifier:** `wallet-local-practical-privacy-v2`
**Supersedes before execution:** `EXPERIMENT-SELECTION.md` SHA-256
`0165ce9cd097a74e7290b52469535aff0d30a9e82684a6296b2f0435a929bb4c`

No fresh wallet, hidden assignment, operation byte or observation existed when
this correction was frozen.

The first freeze contained one inconsistent pair of requirements: it said the
public auxiliary knowledge maps `trial-00`'s exit destination to C, while its
unconstrained relationship shuffle could assign D as that trial's recipient.

Replace only the relationship-assignment paragraph with this rule:

1. choose `trial-00` uniformly from `(A,C)` and `(B,C)`;
2. remove that pair from `{(A,C),(A,D),(B,C),(B,D)}`;
3. shuffle the remaining three pairs with OS randomness and assign the first two
   to `trial-01` and `trial-02`.

This guarantees that the frozen known-exit-identity fact is true and that all
three actual relationships are distinct. It does not select based on observer
predictions or outcomes.

Every other workload value, observer, evidence class, attack, metric, threshold,
control and stop rule in the superseded freeze remains unchanged. This file and
the superseded freeze together are the complete immutable v2 preregistration.
