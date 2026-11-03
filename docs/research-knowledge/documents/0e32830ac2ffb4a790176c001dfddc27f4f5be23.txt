# Fresh initial-pair profile results

This is a fresh public test-only instance. It preserves the reviewed binding and
S7 state algorithms; it does not reproduce the original published setup. The
owner CLI, public ledger replay and owner withdrawal-proof workflow remain
parked. No funds or network transactions are involved.

| Check | Observed result |
| --- | --- |
| Fresh immutable VK | 328 bytes; fully checked before guest compilation |
| Binding/static-key regressions | 14 groups passed |
| Fresh S7 range group | Passed; old state regressions retained separately |
| Fresh checked/compiled host equivalence | Exact independent P1088; genuine altered authorization, malformed proof and identity proof rejected |
| Actual-context guest | 77,752,334 cycles, 170 segments, 1.517 seconds |
| Guest controls | 18/18: three exact journals, 15 typed rejections |
| Selected-host/controls resource use | Peak 441,085,952 bytes; 30.39 CPU seconds including rebuild |
| Genuine outer receipt | Succinct, 223,898 bytes; 302.926 seconds; exact selected image/J; independent CPU verification passed |
| Same-receipt Groth16 compression | 1,169 bytes in 4.444 seconds; unchanged successful claim/J; three SDK negative controls passed |
| Independent CPU verification | Both receipt kinds passed; Succinct SDK plus eight exact context controls, Groth16 fourteen image/journal/seal/fake controls |

GPU samples attributed to the owned CUDA-worker PID observed a 6,096-MiB peak.
The proof cgroup memory peak was 503,586,816 bytes with zero swap. Compression
observed 5,332 MiB on the matching GPU worker and a 1,783,365,632-byte cgroup
peak with the official assets already warm in cache. Samples can miss
brief GPU peaks. The proof unit stopped and all four owned PID/start identities
were absent after cleanup.

Selected identities:

- Groth16 receipt: `e13eaa36d1149bfe873938acf829a9e47d93a6a8014eb61fdad9cb09c6e273f2`.
- Succinct receipt: `345568d0dd58de73f384aa616b5698a7d535c7aaa5335ff74c7a0a94a1b583ce`.
- Image: `e21ab79e3aebdaba0355680d6a17bf0142bf0b3b5bbb687a6f2726499282a0d3`.
- Input11219: `eab451e4701d2fa65c5a5a2cf23a0d1c9483723951c0382989c8e0e9decfaa39`.
- P1088: `70d89b257a6ec611db4775b4c8b0c0db2372cf8f75d084325be89d7d455c6cca`.
- J336: `699697f07565d28faad6e45b9e6daa0a09dbcea3f475d51880a75289f7e49b57`.
- Successful claim: `88f54f54030b2fc884c777a872262679fa15bffca8e613a0f6d40f7d90e92aaa`.

The journal binds the actual offline native ADMIT outpoint, n5/m2 prior state and
1,660,000,000-sompi reserve to the derived n9/m6 successor and 1,580,000,000-sompi
reserve. Native transaction execution, mass/fee acceptance and actual UTXO checks
are separate evidence owned by the native composition harness. The guest itself
authenticates the declared context through the selected receipt claim.

Stage00 source and executable were archived before the three host publication
pins changed. Stage01 explicitly records that delta and the additive host-only
verification/compression tools. The guest/core/locks remained byte-identical.
