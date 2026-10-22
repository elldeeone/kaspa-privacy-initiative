# v6 constraint and S7 state boundary qualification

All 30 frozen v6 cases matched their expected outcomes. The S7 host tests also
passed: seven groups on the first snapshot, followed by one targeted high-index
group on an append-only snapshot. No acceptance bug was found in these cases.
Production circuits, binding/state cores and published fixtures were unchanged.

## What this adds

The existing harness's `amount-overflow` mutation did not rebuild the affected
commitment/root/NF, so its rejection could be caused by membership rather than
arithmetic. The new constraint-only binary rebuilds those dependencies and tests
exact MAX versus MAX+1, amount floors, zero/padded outputs, nonzero fees and
one-sompi inflation/deflation. It also isolates 16-bit positions, count slack,
real-input permutation and canonical inactive-input fields.

The frozen [plan](../BOUNDARY-TEST-PLAN.md) and [case manifest](evidence/full-constraints-01/case-manifest.json)
precede execution. All 28 complete systems synthesized exactly 4,372,824
constraints: 11 satisfied and 17 unsatisfied as expected. Two malformed path
lengths returned the expected synthesis error after 1,928,055 partial
constraints; they are not counted as complete systems. The baseline pilot was
reused once, without re-execution. Every original outcome/diagnostic is retained
in [suite-result.json](evidence/full-constraints-01/suite-result.json).

The private relation accepts the frozen count-65,536 and `u32::MAX` examples.
This is the documented component boundary: it proves real positions and
`position < declared count`; native/S7 context must authenticate the allowed
historical count/root. These positives are not native acceptance or a binding
bypass. The position-65,536 low-16-bit alias rejects.

## State composition

The first [seven-group run](evidence/s7-tests-01/qualification.json) verifies the
published genuine pair and adds:

- Exact P/J336/next-state invariance after swapping bundles; duplicated bundle
  rejection by NF uniqueness.
- An independent full-array Merkle oracle reconstructing the original n5 input
  byte-for-byte and supplying n7/n65531 predecessor contexts with exact J336.
- Authenticated old-root second witnesses rejecting precisely at
  `NullifierRoot(1)`, `CommitmentOccupied(1)` and `HistoryOccupied(1)`.
- All 11,219 short frames plus one trailing-byte frame rejecting, four even-NF
  boundary candidates for every legal odd CM count, and 67,072 numeric-LE
  comparator comparisons against a two-u128 oracle.

The [high-index addendum](../BOUNDARY-HIGH-NF-ADDENDUM.md) froze one further
discriminator. Its [targeted run](evidence/s7-high-nf-01/qualification.json)
checks a genuine pair against a supplied n65531/m131054 context, with an actual
predecessor above 65,535 and append indices 131055..131058. It matches the full
independent J336; authentic low-16-bit append/predecessor aliases reject with
`NullifierOccupied(0)` and `NullifierRoot(slot)`.

These supplied trees qualify local transitions, not accepted/reachable history,
authentic genesis, backing, native execution, guest execution or owner exits.
The unchanged production state core remains SHA256
`d0aa212a1652642d0b2475fac903e0ab18c8276317cc0107305b8d51fadd200f`.

The seven-group source was `bbe1ce75...12487`; the added-test source is
`ab5006cf...12e81`. The former's entire 13,830 bytes, including every shared
helper and existing test, remain an identical prefix of the latter. The
[append-only audit](evidence/s7-high-nf-01/source-addition-audit.json) retains
both full hashes. This is seven-plus-one qualification, not a single current
8/8 execution. Independent adversarial source review found no expectation
blocker; no expectation was changed after execution.

## Resources and reproduction

| Run | Wall seconds | Owned-cgroup CPU seconds | Peak bytes |
| --- | ---: | ---: | ---: |
| Warm source build | 18.77 | 57.18 | 978,481,152 |
| Baseline pilot, counted once | 67.28 | 454.22 | 1,047,379,968 |
| Remaining 29 constraint/shape cases | 1,385.08 | 9,195.77 | 1,049,460,736 |
| Seven S7 groups, compile included | 20.44 | 20.45 | 165,179,392 |
| One targeted new S7 group, compile included | 30.71 | 30.72 | 165,765,120 |

The constraint unit was limited to 8 CPU/10 GiB RAM/zero swap. S7 tests used
1 CPU/2 GiB. All owned units finished and were stopped with PID zero and empty
cgroups; terminal evidence is retained. These are constraint-check timings,
not trusted-setup or wallet/proof-generation costs.

**Measurement limitation:** external `/usr/bin/time` measured the bwrap wrapper
rather than its PID-namespace descendants. Those raw files remain available,
but their CPU/RSS values are unusable for circuit cost. The table uses owned
cgroups; per-case internal constraint wall times remain usable. Per-case peak
RSS was not measured correctly, and no cases were repeated to replace it.

The exact warm Rust 1.95 `/src`/`/cargo` build recipe is retained in
[build-warm.sh](evidence/source-build-01/build-warm.sh). The new binary supports
only `list` and `check FIXED_CASE_ID`; it has no file-input/proving/setup API.
Rebuild `kpi_v6_boundary_check` from this checkout with the locked shared-pool
manifest, then run the fixed case IDs. The two S7 commands and source snapshots
are retained in their `command.json` and `source-snapshot/` directories.

[MANIFEST.json](MANIFEST.json) hashes every retained packet file and the selected
source identities. The 9,283,992-byte compiled checker and private build caches
are omitted from this public packet; its exact binary hash/build recipe are
retained, and the local bytes were preserved. No setup, proof generation, PK
restore, funding, broadcast, owner CLI, ledger replay or withdrawal workflow ran.
Passing tests are evidence about this implementation, not cryptographic
correctness, privacy, accepted-chain status or production safety.
