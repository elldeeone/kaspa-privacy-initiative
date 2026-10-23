# Fresh optimized exact-SHA proof: closed first observation

The fresh optimized Groth16 setup and genuine proof passed checked
verification on four CPU equivalents. **Both original performance targets
still miss:** resident proving took **11.1696s** against 10s; whole-process
peak RSS was **4.009258 GiB** against 4 GiB. The excess is 9,940,992 bytes
(about 9.48 MiB). Neither target was rounded or changed. No repeat was run.

| Observation | Measured |
| --- | ---: |
| Fresh setup | 28.7164s |
| Resident proof plus original checked verification | 11.1696s |
| Additional checked verification | 0.00255s |
| Official uncompressed serialization and fsync | 1.5663s |
| Complete uncompressed parameter SHA256 | 0.6599s |
| Whole process wall | 42.32s |
| User + system CPU | 133.46s + 4.66s |
| Maximum process RSS | 4,204,012 KiB |
| Observed cgroup memory high-water mark | 4,313,493,504 bytes |
| Swap | 0 |

The allocation was four CPU equivalents, 16 GiB RAM, zero swap, network
isolated, with a generous one-hour bound. The 4 GiB and 10s thresholds were
measurement gates, not abort limits. External time accounting and the
0.5-second cgroup samples remain in [run-01](run-01/report.json). The unit
finished successfully, inactive/dead with MainPID0 and an absent/empty owned
cgroup. `/proc/self/status` snapshots are cumulative high-water/current RSS,
not independent per-phase peak estimates.

The semantic fixture is the unchanged public primary two-real-input,
two-recipient case, SHA256
`e59a1dd7f93c1bbe7c6176e589accc558efa97907411508a12f6cbdfbf704a06`.
The prior synthesis measured 3,497,893 optimized constraints. This fresh
setup produced the expected 3,459,644 A/B query lengths, 3,459,641 L-query
length and 4,194,303 H-query length, confirming the `2^22` domain shape.
Pinned source/fixture construction and those actual dimensions identify the
matrix instance; no raw matrix digest is claimed.

There is no PK/matrix-loading mode or mount. One fresh OsRng setup generated
the new parameters; that same resident PK generated one proof. Its VK
differs from the old parameter VK. No old key, closed library, active trial
or native policy was replaced.

The fresh [VK328](run-01/verification-key.bin) has SHA256
`7d9755628956f8264ce002375f0b77ebe5bdbfd15ce82817e1450ae3ada88ec3`.
The [Proof128](run-01/proof128.bin) has SHA256
`b68e18629ec8cba8520b3afaa3727b75737bd73183800d9e24773259d869ca4c`.
The [report](run-01/report.json) SHA256 is
`e2181f428d092cd9d9a1cbcd05d9958716a8d0cff8daf977a93be5698b07792e`.
The 1,375,522,096-byte uncompressed PK stays local, SHA256
`931160ff4327d5c64eba85e4c8fa27de93488a09ad53c4b008cdd8c040b34ddd`.

This extends the independently reviewed exact-SHA source/truth/known-answer
and SAT evidence to a real fresh setup/proof. Three small runner tests also
passed. The candidate's inherited 17 full constraint negatives were not run
by this experiment. This is performance and bounded host proof evidence,
not p95, whole-wallet qualification, a cryptographic audit, native acceptance,
privacy or a testnet/chain result. Other runs used different caps and
workloads; they are context rather than a controlled speedup comparison.
