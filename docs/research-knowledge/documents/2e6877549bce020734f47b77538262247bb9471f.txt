# Offline native script-reuse evidence

[Report](../../ADDRESS-REUSE.md) and [prospective specification](../../ADDRESS-REUSE-SPEC.md).
Seven genuine proofs, synthetic parent UTXOs, local native validation; no funds,
broadcasts or chain-acceptance observation. This is a constructed two-wallet
diagnostic, not the 32-role privacy workload or a cryptographic audit.

- `native/matched` and `native/different-index`: complete public native lineage,
  selected funding-parent bodies, public descriptor/VK, expected head, replay
  summary and declared funding-owner directory. Matching index reuse occurs
  only in the matching arm. Each arm reconciles 32 = 30.4 + 1.6 tKAS.
- `native/summary.json`: a derivative summary of the private native execution
  record. Operational wallet/receipt/control labels are omitted. Its source
  hash identifies the non-exported full result; the derivative has its own hash.
  Source/binary before/after manifests and parameter identities are retained.
- `evaluation/code` and `evaluation/freeze.json`: exact frozen executable source,
  specification and dependency identities. The copied specification ends in
  `.md.txt` so historical links are not interpreted as current documentation.
- `evaluation/runs`: isolated controls, each arm's predictions and seals, then
  separate scores. Only the matching final linked profile forces all three
  fields: sender 0, recipient 1, amount 1,920,000,000 sompi. These are conditional
  on the declared startup and wallet assumptions. Hypothetical witnesses in
  predictions are arithmetic alternatives, not recovered secret notes.
- `evaluation/prediction-batch.json`: both predictions sealed before any scorer.
  Private truth paths/hashes identify withheld artifacts; full truth is absent.
  Independent native replay outputs and the final scoring summary are retained.

Each observer saw only its own four native source files and funding-owner
directory, with no backup, truth, other arm, driver/specification or operational
logs mounted. **The combined export is not a valid isolated control view:** the
counterfactual arms share keys, so exposing both would contaminate the control.
Use the documented isolated runner to reproduce the observation boundary.

The owner associations and self-bootstrap schedule are declared auxiliary
information. Script equality alone identifies the same native spending
condition. It does not establish human identities or generic sender/amount
disclosure. The report distinguishes a separate analytic recipient deduction
from the stronger measured model. No anonymity rate is implied by ambiguity.

`SHA256SUMS` covers every exported file except itself. The allowlist excludes
backups, receiving envelopes, private selections/derivation indices, complete
truth and wallet inspection logs. No compiled binaries or proving key are
exported; exact hashes bind the retained executable and public parameter bytes.
