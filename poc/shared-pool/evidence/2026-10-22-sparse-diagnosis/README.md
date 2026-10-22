# Sparse attack diagnosis: public evidence

See the [report](../../WORKING-BALANCE-SPARSE-DIAGNOSIS.md) and
[pre-truth contract](../../WORKING-BALANCE-SPARSE-DIAGNOSIS-SPEC.md).

`summary.json` contains aggregate counts only. `freeze.json`, `public-seal.json`
and `completion.json` bind the new sources, old experiment and execution order.
The four `trace-*-result.json.gz` files are public hypotheses, not truth: each
contains all 64 observable targets and every selected-key construction from one
arm/profile. Corresponding process, isolation and input receipts bind their
execution. `manifest.json` binds stored and decoded bytes. `SHA256SUMS` binds
the complete exported package.

`validation.json` records the 35 public controls, unchanged 1,506-job original
seal audit and exact prediction replay. `independent-review.json` records a
separate agent's independent ancestry/flow recount, using the same retained
synthetic truth; it is not independent real-world evidence or attestation.
The independently written [recount script](independent_recount.py) uses no
diagnostic helper imports. With authorized access to the retained staged data:

```bash
python3 -B independent_recount.py /path/to/retained-diagnosis-directory
```

It prints aggregates only and never opens the original experiment or seed.

The original public data and frozen observer are in the
[earlier export](../2026-10-21-working-balance/README.md). Public book/guess
reproduction needs no seed or truth. Recomputing diagnostic correctness and
actual ancestry requires the retained private truth; the public aggregate alone
cannot independently establish those joins.

The new private attempt is retained at
`/home/luke/kpi-private/working-balance-sparse-diagnosis-20261022-01`.
No private truth, detailed classification, honest wallet records, backup or seed
is exported. The original experiment and its rejection remain unchanged.
