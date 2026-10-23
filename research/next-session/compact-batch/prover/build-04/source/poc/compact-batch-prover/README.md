# Matched compact2 / wide32 prover

ADR0057 implements new fixed-role BN254 Groth16 relations for the separately
reviewed compact native policy. It reuses the old SHA256/HMAC, notes, positioned
nullifiers and current private membership relation, with the new Auth528 list
hash/mode/range binding. It never funds, broadcasts, encrypts or authenticates
accepted-chain currentness. Tests are implementation evidence, not soundness.

The concrete initially unfunded instance is selected in `trial-selection.json`.
Each role's parameter selection starts false. Fresh setup uses OS randomness;
old PKs and matrices are never loaded or reused. A compact owner does not need
the wide PK. No private witness accepts a role override.

```text
kpi-compact-batch-prover shape ROLE PUBLIC-CANARY NEW-OUTPUT
kpi-compact-batch-prover check ROLE PUBLIC-CANARY NEW-OUTPUT
kpi-compact-batch-setup session ROLE SHAPE-CANARY NEW-OUTPUT NEW-PK-OUTSIDE-GIT
kpi-compact-batch-prover prove ROLE SELECTED-PK WITNESS-FD NEW-OUTPUT
kpi-compact-batch-prover loader-only ROLE SELECTED-PK NEW-OUTPUT
kpi-compact-batch-prover verify ROLE AUTH528 PROOF128
```

`ROLE` is exactly `compact2` or `wide32`. `shape` measures finalized constraints,
official FFT size and canonical coefficient/index matrices, never assignments.
Compact modes0/2 must have identical matrix fingerprints. `check` does the same
finalized SAT check without making a redundant matrix-hash claim for each
malformed assignment. These commands are development controls; public canaries
are explicitly DO_NOT_FUND and independent from any private workload.

The setup emits public role/key/dimension/source identity and then accepts one
JSON object per line, `{"fixture":"PRIVATE-FILE","output":"NEW-OUTPUT"}`,
or `quit`. Private fixture paths and all alternative preparations stay private.
The role is fixed for the entire session. It records the actual finalized setup
matrix and query dimensions before retaining the key; setup artifacts belong
outside Git. `select_parameters.py` is a root-only canonical metadata helper,
never capsule-selected authority. It compares fresh setup shape/source identity
before installing that role's new compiled manifest/VK pins. Rebuild afterward.

Owner `prove` authenticates compiled role/manifest, exact full owned PK bytes,
exhaustive decoding and extracted VK/query dimensions before emitting
`parameters-ready`. Only then does it open the inherited witness FD. Missing,
wrong-role, corrupt or trailing parameters must fail without consuming witness
bytes. Its fixed private errors never include parser values or private paths.

Only selected verified public Auth/proof/VK and opaque identities are written.
Backups, witnesses or their hashes, receipt maps, discarded quote/Auth/NF pairs
are never exported. Raw unbroadcast alternatives remain private even after a
later preparation confirms. Public parameters/history availability and honest
development setup remain assumptions; a capsule hash does not prove currentness.

See the phase's results for measured outcomes; this package alone is neither
accepted native backing, fee qualification, privacy qualification nor readiness
for a funded testnet trial. No mainnet, real funds or privileged rescue is used.
