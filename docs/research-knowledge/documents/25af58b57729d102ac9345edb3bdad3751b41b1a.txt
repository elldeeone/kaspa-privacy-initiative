# 32-role privacy test: public execution checkpoint

The [report](../../POPULATION-PRIVACY.md) and
[specification](../../POPULATION-PRIVACY-SPEC.md) define the scope.
This checkpoint is incomplete and contains no privacy verdict.

`attempts/method-01` retains:

- The pre-generation freeze and exact executable source snapshots. The copied
  specification uses `.md.txt` so historical links are not reinterpreted here.
- Solver dependency file hashes and prior native-calibration identity.
- The passing isolated controls: 13 model controls, 545 exhaustive proposition
  comparisons, and 13 workload controls.
- Four seed-bundle commitments and the generation summary for eight histories.
  Individual-role truth aggregates, seeds and private generated truth are absent.
- The first persistent history's public input and pooled participant view.
- Isolation/input manifests and an immutable first progress-log checkpoint.

The original local attempt is `/tmp/kpi-32-role-20261020-method-01`.
Checkpoint 1 remains unchanged. `attempts/method-01-stopped` adds the subsequent
interruption record and terminal logs: no initial SAT answer or prediction.
Do not overwrite the original attempt or interpret checkpoint 1 as live status.

`attempts/method-02` and `attempts/method-03` retain the compact-index and
monetary-flow replays' frozen sources, controls, input/isolation manifests and
interruption records. Each ran for approximately eight hours without an initial
SAT answer or prediction before being stopped to release resources.
`attempts/z3-probe-01` retains an independent original-model Z3 probe, exit 137,
and kernel evidence identifying its process as an out-of-memory kill.
All used the same first persistent public history and pooled view. No new
seeds or workloads were sampled. No scored result exists in these attempts;
solver exhaustion is not evidence of privacy.

`attempts/method-04` retains the completed local-relaxation batch: frozen
sources/specification, 38 passing controls, all eight public inputs/pooled views,
sealed predictions, isolated scores and completion summary. All 512 ordinary
targets completed; no undisclosed forced facts were found, including among the
99 primary payments per arm. Every case's truth satisfied both original full
models after its prediction seal. This weaker relation also leaves prompt
amounts inconclusive even though method 05 recovers them exactly; it cannot
support a privacy claim.

`attempts/method-05` retains the completed deterministic guessing batch: frozen
sources/specification, 33 passing controls, all eight public inputs/pooled views,
predictions, prediction seals and the pre-scoring batch seal, isolated scores and
completion summary. Each of the four request sets has paired arms; there are
99 primary eligible payments per arm. Prompt cashout reveals all 99 amounts
exactly. The best of three fixed simple persistent-amount attacks scores 5/99
within 10%, with zero exact matches. These measurements cannot qualify privacy.
Every history's pinned truth passed both original full models and accounting
inside a separate scorer; no seeds or complete private truth are exported.

Large prediction files are stored as `result.json.gz`. The
`compressed-predictions.json` manifest gives the original uncompressed SHA-256
and byte count, matching each prediction seal. Decompressing restores the exact
sealed bytes. Each attempt's `SHA256SUMS` covers the stored export files.
Copied Markdown specifications/method notes use `.md.txt` to preserve their
historical bytes without treating their links as current local documentation.

`SHA256SUMS` covers every file in the attempt except itself. Public inputs and
pooled records contain synthetic amounts and role identifiers that are declared
observer knowledge. Hypothetical solver witnesses, if later retained, are
alternatives from inference and must not be labeled recovered private truth.
The observer does not receive this evidence directory or generation summary:
only its selected public file and one selected view are mounted.

This is a modeled privacy experiment. No new native transactions, proofs, funds
or chain acceptance are represented by its generated histories.
