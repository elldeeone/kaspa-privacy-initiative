# Offline fresh-proof evidence

[Report](../../FRESH-PROOF.md), [pre-run specification](../../FRESH-PROOF-SPEC.md),
[self-review](../../FRESH-PROOF-REVIEW.md). No new chain transactions or fees.

- `summary.json`: three matched comparisons, all-exit source/note candidates,
  recency and uniform-prior baselines, both observation horizons, proof costs,
  native-control results and complete drainage. Old-arm values are aggregate
  only; no old proof, authorization, transaction ID or nullifier map is exported.
- `{singleton,low-a,low-b}/fresh-arm/`: fresh history's native transaction JSON,
  explicit synthetic input contexts, metrics and chain-only projection. Its
  header times are simulation inputs, not accepted block headers.
- `fresh-observer.json`: exact remaining source/position candidates, both models
  and horizons. Observer only saw this history; it did not see this README,
  workload specification, private labels, seeds, ground truth or the old arm.
- `*-settlement-{result,isolation}.json`: old/fresh exits independently rebuilt
  with no wallet, proving key, host home or network; same proof/auth retained.
  Private old transaction/request output is deliberately omitted.
- `*-native-replay.json`: native Full, relay-policy and script-metering receipts
  for each saved transaction with supplied synthetic UTXO contexts.
- `*-observer-isolation.json`, `prover-isolation.json`: namespace boundaries.
- `source-pins.json`, `binary.json`, `validator.json`, `export.json`: source/spec,
  executable, analysis software and exported data hashes, plus secret-disclosure
  checks. `resources.json` separates measured timing from unmeasured prover RSS.

Only the fresh histories are public. Both pending bundles, every old history,
private settlement requests, wallet secrets, truth, rejected transactions and
raw error logs remain outside Git. The singleton old/fresh authorization is
identical because its root does not grow; its unused old proof is still excluded.
The old-side comparison needs those private files or a new randomized run.

Amounts are integer sompi; monetary units in the report are conversions. Native
and observer validation concern this synthetic model and pinned implementation.
Candidate counts do not establish people, probabilities or real-world anonymity.
`export.json` hashes the allowlisted machine artifacts; this explanatory README
and the separately saved test receipts are added afterward.
