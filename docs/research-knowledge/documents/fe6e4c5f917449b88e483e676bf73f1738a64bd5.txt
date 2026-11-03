# Fresh selected-HMAC proof performance

**One fresh genuine proof verified.** With four Rayon workers and a 400% CPU
quota, setup takes 26.802 s and resident proving plus original checked verification
takes **10.495156 s**. An additional checked verification passes. Whole process
wall is 39.65 s; GNUtime peak is**4,011,128KiB (3.82531 GiB)**, swap 0.

This one proof process is below 4 GiB by 187,572,224 bytes. The unchanged 10-second
warm-proof screen **still fails by 0.495156 s**. Neither p95, a complete wallet nor
the four-physical-core reference laptop is qualified. The input fixture and
public state were already prepared. No identical performance rerun was made.

The new matrices use 3,199,529 constraints, 3,164,457 witnesses and a 2^22 FFT
domain. Actual A/B query lengths are 3,164,460; L 3,164,457; H 4,194,303. The CLI
has no old-key or matrix loader. OsRng creates one fresh setup, whose PK stays
resident for the proof. Original checked proof/VK validation is unchanged.
Native policy and the funded TN10 trial were untouched. This is no security,
cryptographic correctness or privacy proof.

New VK SHA256 `9492aa0f16e39e783c9a5bd99ed2dd1567ad0684f114c6d61a77df9d7b143ef7`.
Proof128 SHA256 `5f708303f42aec73aa7c7e551a38225581d17c0ff306772f3f7311edf975a355`.
Official uncompressed PK is 1,281,063,216bytes,
SHA256 `77537d3f6786fd24ffbf2b7bed1c5cad369dec551985ba392539e0dda7d73c92`; it remains 0600 outside Git.

The first command used a relative systemd script path and failed before any
build or proof. Its log remains; absolute-path launch then built and passed 3
cheap source/fixture checks. Only one heavy setup/proof ran. The unit is inactive,
dead/PID0 and its cgroup absent/empty. Source/build/runtime freezes, measurements
and failure logs are retained.

After the run, root requested cosmetic formatting in current source. The exact
executed source remains in build-01/source and its original PLAN/runtime/report
pins remain unchanged. POST-RUN-FORMAT-ONLY.json maps current source to that
executed snapshot. Only two test assertion layouts, CLI usage layout and the current
CLI's embedded formatted-library hash changed; circuit/SHA/verifier unchanged.
No key/proof was regenerated for formatting.

The earlier Ch/Maj candidate's 11.17 s / 4.009258 GiB failed result is unchanged at
[its report](../exact-sha-proof/RESULTS.md). The 17 full-transfer negative controls have
not run on this candidate; its independent exact-padding/HMAC/selector/SHA tests
and full SAT are separate sizing evidence. Broader adoption remains open.
