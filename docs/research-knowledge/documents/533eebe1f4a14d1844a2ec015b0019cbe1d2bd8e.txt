# Public parameter build and cache checks

This records parameter provisioning under ADR-0055, not payment-lifecycle or
testnet readiness. Native body validation, accepted-chain backing, the six local
proofs and four cold-owner actions require their own evidence.

The fresh trial is `fc8dfe40-3080-4650-bc73-ab7e426da13a`, domain
`bd9a7227d8f027f1fa1e284c2ff9af86fbce8722eca1e8e043b6d7b9a5cba4bc`.
The root's [reuse selection](../TRIAL-REUSE-SELECTION.json) preserves the
ADR-0053 template and ADR-0054 executable assumptions. All 17 source files were
checked: only the domain literal and public trial-selection file changed.
The selected cold source subsequently changed exactly three public pin files.
Prior prover source and closed evidence have no tracked diff.

| Artifact | Identity/result |
| --- | --- |
| Setup source manifest | `0df06d8deff5854828feb0c2eb42ee672f4ad105a923e9087614b1ab2b9b399b` |
| Fresh setup executable | `24d23978bb0b54449f26f075f2d41e1ba15c56c1be87db72b91eb04d248dd44e` |
| Compiled core/build identity | `a26f7b4958168f26536b9fe90e30fa9abd030aa7fa8c04555022ad2c426b747d` |
| Measured constraint shape | 3,231,025 constraints; 3,195,131 witnesses; 3 instances including one |
| Actual queries | A/B: 3,195,134; L: 3,195,131; H: 4,194,303 |
| Fresh VK328 SHA256 | `dade8f90f1bec1c9b150f5eb126d73a1c8a1959ef1fb9da1178820debf693bae` |
| New public parameters | 1,290,878,896 bytes; SHA256 `95729cb3561e839666026afadbbd8e9c77f199c021caf47e6612616a1b7f191f` |
| Root-selected canonical manifest | `b440d08fddcdbbfb7d6b8355ab097a7bedd3fb85b8aa228f07070d4fcb3a91d0` |
| Cold source manifest | `df3959fdd785ed61a7939f8db845d2c7dcb4732e400d136534f9c01bf7ff99e5` |
| Tested cold executable | 3,644,712 bytes; SHA256 `3252c28f2e3b08aa85aab5ff82dc3adf481dec84dbb9d5514e0fb69012250b43` |

Source-only compilation of both binaries took 9.38 seconds; the selected cold
binary compilation took 7.79 seconds. No unchanged parser/backend/unit suites or
old matrices were rerun. The sole fresh setup measured its own finalized CS;
counts were not imported from a prior domain.

The [selected-loader control](loader-01/results/report.json) passed 12/12 checks.
It loaded the newly mirrored public parameter file, hashed the complete owned
buffer before decoding, required decode exhaustion and checked VK/source/build/
query identity. Its read/hash/decode phases took 0.778/0.545/1.764 seconds.
The missing-PK negative retained all 302 offered public-canary bytes and emitted
no readiness or proof output. The control received no seed, owner witness or
backup. Build and loader units stopped inactive/dead with PID0, exit0 and no
reported cleanup error.

The parameter mirror is outside Git, file mode 0600 under a mode 0700 directory.
No old parameter blob was read or mounted. Warm OS page cache was possible;
these are single local samples, not p95, cold-download, remote-mirror availability
or owner-proving performance qualification. Parameter hashes establish identity,
not setup honesty, trapdoor erasure or cryptographic security. The ordinary
selected 0500 executable/read-only-mount path retains the explicit trusted-host
and release-immutability assumption.
