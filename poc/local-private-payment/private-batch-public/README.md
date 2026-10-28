# Public verification for RFC-0030 / ADR-0074

This subtree implements the public verifier and native covenant for the new
three-spend/six-output native-KAS research profile. `component-profile.json`
now selects the three actual new role keys for the prospective unfunded pool;
this is key configuration, **not financial qualification**. `outer-selection.json`
contains the resulting image identities with `selected:false`. No aggregate
proof, R0 receipt, native payment acceptance or funding readiness is inferred.

`common` verifies the genuine aggregate proof and six genuine Output proofs,
the exact public CM/NF transitions, current context and commitment balance.
`guest` performs those checks inside the R0 program. `host` supplies execution,
receipt verification/compression and native-proof encoding. `native` binds the
actual reserve, state, outputs, fee, immutable successor and selected image/journal.
The direct AuthExit branch uses its own genuine proof and requires no R0 receipt.

The payment projection is 10,685 bytes; the R0 journal is exactly 104 bytes:

```text
KPBAJR01 || D32 || component_manifest_SHA256 || SHA256(payment_projection)
```

`proving/build_guest.py` builds offline in a network-isolated namespace with
the transitive source closure, readonly registry/git cache, authenticated
compiler archive and an owned build cache. It never executes or proves a guest.
An unselected build requires `--allow-unselected-template`. Every attempt uses
a fresh output directory and retains its source, tool and build identities.
Selecting actual component keys requires a new guest build and image.

Later builds can reuse an externally selected, previously reviewed archive
derivation with `--derived-toolchain-receipt` and
`--derived-toolchain-receipt-sha256`. Every readonly leaf is reauthenticated;
the exact receipt's origin remains an explicit trust input. The retained build04
receipt is `305d7370090bee9d5575cde6dbc206fe3a6a3c34a4633da046d15fcea82baa5a`.
All 389 leaves passed a separate guarded reuse admission. New attempts retain
the already-guarded source bytes under their fresh `source/` directory.

The 2026-10-28 template build succeeded in 62.76 seconds. Its admitted raw ELF
SHA256 is `1fb2299901d7d06c04378f65101d7e8d914222d3727b15305f2d8b5161e3ad8f`
(1,201,464 bytes). The compiler/runtime/rustlib/linker closure was materialized
from retained authenticated archive
`100b597d605b706bec94e1d32bfaaf5851df8d75173f986d4b56a3e90916be53`.
Its official internal hardlinks were flattened to independent readonly leaves;
the old SDK was preserved. This ELF is **template build evidence only**.

The [native documentation](native/README.md) records a separate genuine,
unfunded direct-exit component result: both terminal and continuing cases passed
actual Native Full and input scripts; 21 mutations failed actual input scripts.
Payment metadata in that experiment are explicitly opaque and unselected.

The subsequent actual-key guest build succeeded in 3.07 seconds, reusing the
same previously authenticated readonly SDK. Component manifest
`2598cd4baa438e6fb5c95bc4d1f6b8f1f7db607879f428c43f82a5247aca7f36`
produced raw ELF `10d7f4052de6353840e213b36a15750d6b2abb92f685a7e7eacab5b081f3105b`
(1,204,436 bytes), program
`af7064025876e1045a88f42119ef95a79b1a6a44334a43fcad0d2528d840450c`
and image `d62eaf8b01ed970048bd8f2565e55ae9f2af3dcad8b7f12d94a40819805dd119`.
The old admitted host was used only for the generic public wrap operation.
There was no guest execution or proof. [Role-selection provenance](evidence/2026-10-28-real-role-selection/SELECTION.json)
retains all actual public parameter identities; no old financial role key is reused.

Remaining integration requires the genuine aggregate proof, a matching new host
and explicitly selected image after qualification, actual R0
execution/proving/compression, native payment controls, and a complete testnet
rehearsal with confirmed terminal payout. None of these later results follows
from template compilation or the conditional direct-exit experiment.
