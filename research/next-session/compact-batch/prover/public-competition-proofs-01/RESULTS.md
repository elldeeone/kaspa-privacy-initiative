Three new genuine public Groth16 proofs exercised same-note competition across both batch roles and REVEAL. They used the unchanged selected B05 prover, matched role parameters, and an empty witness FD until whole-PK authentication returned exact READY. All notes and signing scalar1 are public `DO_NOT_FUND` controls, disjoint from actual owner notes.

| Public proof | Cold wall time | Native outcome |
| --- | ---: | --- |
| compact2 from shared current state | 12.819s | Full and all engines accept |
| wide32 from the same state and two real NFs | 29.205s | Full and all engines accept |
| fresh compact2 after accepted REVEAL | 13.125s | Valid private proof; native duplicate-NF guard rejects before G16 |

The first two are mutually exclusive alternatives spending the same pool UTXO, not two settled payments. The fresh third proof binds the actual post-REVEAL outpoint, reserve of 31 billion sompi and NF count 4, with correct current CM paths and the original two real NFs. Native Full rejects it with `SignatureInvalid(VerifyError)` at 158,752 units. Two current-state REVEAL duplicates also reject after the private roles; two unchanged-proof cross-role rebases reject stale Auth and are labeled only as stale-Auth evidence. Lifecycle retains all eight native cases and their reconstruction checks.

`PUBLIC-STATEMENT-CHECK.json` independently checks the three emitted public Auth byte relationships. `SUMMARY.json` records exact proof/Auth identities and hashes of the native result reports. Controllers, resource logs and cleanup observations are retained. Minimum sampled host MemAvailable stayed above 3GiB; every standalone proof unit was collected with manager MainPID0. Kernel remaining-process observations were unavailable, not measured zero.

This additive evidence does not claim chain backing, a live accepted-chain race, privacy, or relay-fee qualification. Fee 1000 is deliberately underpaid in these public controls. The original prover/publication lists, package pins, sources and prior results were left unchanged. A separate finite list covers only this additive directory.
