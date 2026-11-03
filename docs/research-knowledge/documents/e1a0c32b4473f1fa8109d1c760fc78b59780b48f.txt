> Imported documentation snapshot. [Canonical status and ownership](../../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# Public CPU-adapter feasibility preflight

**Decision: runtime metadata GO; execution NO-GO under the current Mac hold.** A compatible NumPy installation already exists, but this lane has not imported it or the adapter. The parent reported that C+D reference passed exact parity and sampled 162 MiB RSS, then stopped the pooled reference after 57.88 seconds when system swap exceeded the preset limit. Pooled has a partial profile and no parity result. There is no retry or CPU-adapter launch authorized by this report. Root may revisit capacity or move the comparison to Forge after terminal release; v2 review remains a separate gate.

## Existing runtime identity

The workspace dependency locator returned bundle `26.1020.11348`. Its interpreter is `historical-mac-runtime:codex-primary-runtime/dependencies/python/bin/python3`, resolving to `python3.12` in the same directory: CPython 3.12.14, arm64. NumPy 2.3.5 is already present at `historical-mac-runtime:codex-primary-runtime/dependencies/python/lib/python3.12/site-packages/numpy`. The distribution metadata says Python `>=3.11`; the wheel tag is `cp312-cp312-macosx_14_0_arm64`, consistent with this CPython ABI and the Mac's reported macOS 27.0.1 arm64 platform. Its version matches v1 `requirements.in`.

[NUMPY-METADATA-PREFLIGHT.json](NUMPY-METADATA-PREFLIGHT.json) records exact interpreter/package paths, WHEEL metadata, RECORD digest and hashes of `__init__.py` and the `_multiarray_umath` extension. Only stdlib metadata inspection ran, under `-I -B -S`; `numpy` was absent from `sys.modules`. No import/link test, array allocation, adapter execution or install was performed. Metadata agreement does not prove successful dynamic-library loading or audit the whole shared bundle.

For a later separately scheduled direct CPU check, use this interpreter rather than modifying the configured Homebrew Python. A `-I -B -S` runner would explicitly add the verified capsule and bundled site-packages paths, avoiding automatic site/.pth processing. Record that this Python 3.12 runtime differs from the existing Mac reference run's Python 3.14.6 and from Forge's future locked Linux environment. A fair elapsed comparison requires a reference measurement in the same runtime/conditions; the earlier profiled Python 3.14 run is correctness context, not the timing control. Keep BLAS/OpenMP-related thread limits at one before any NumPy import, and retain the parent-owned RSS/time/pressure controller.

## Fixture-derived allocation bounds

The immutable v1 manifest remains `a3281bbc72d32627c16fba035fb01937f7963555da6ff3e39abe513110735270`. Both allowlisted views contain the same 173-event public ledger and 64 targets. After the minimum target (event 32), there are exactly 76 payouts: 44 whole and 32 partial. The observer considers `C(76,2) + C(76,3) = 2,850 + 70,300 = 73,150` subsets (`working_balance_observer.py:205-208,323-350`). There are 37 known notes at least FLOOR in C+D and 81 in pooled, obtained by a small field inventory of the public fixture/view using the insertion sites at lines 168-189. No subset enumeration or observer execution was used.

Each whole payout creates at most one base residual plus one residual per eligible known note (lines 283-300). Each subset creates at most one base row plus one co-input row per such note: merged value intervals are disjoint, so a note position cannot be added twice for one subset (lines 304-350). Owner, timing and value filters only reduce those counts. With `K` known positive notes, a safe loose bound is therefore `R <= (44 + 73,150) × (1 + K)`.

| Engine | K | Maximum rows | Packed int64 bytes, 7 × 8 per row | Packed MiB |
|---|---:|---:|---:|---:|
| C+D | 37 | 2,781,372 | 155,756,832 | 148.54 |
| Pooled participant view | 81 | 6,001,908 | 336,106,848 | 320.54 |

Pooled `observe()` retains its participant engine while constructing a second C+D engine (`working_balance_observer.py:563-571`); their combined loose packed-array ceiling is 491,863,680 bytes, or 469.08 MiB. The largest possible candidate value is bounded by three times the largest payout plus fee, 432,064,200,000, comfortably within int64. Exact fixture inventory and arithmetic are in [FIXTURE-ALLOCATION-BOUND.json](FIXTURE-ALLOCATION-BOUND.json).

## Meaning for the pre-allocation defect

For these exact hashes, the **per-engine raw packed array cannot reach the v1 1 GiB rejection threshold** (`adapter.py:67-70`). That particular over-limit exception is unreachable. The code still constructs reference candidate dictionaries, `_rows`, an identity-to-index dictionary and every seven-element Python list before checking the array size (`adapter.py:52-70`). Those allocations are not covered by the raw-array byte limit.

The existing CPython 3.12 reports 112 bytes for one seven-slot list, before the referenced integers, outer-list storage or index dictionary. At the loose row ceilings, packed inner lists alone would occupy up to about 297.08 MiB for C+D or 641.07 MiB for pooled while the NumPy conversion is taking place. Together with the array, outer/row pointers, original candidates, indices, masks, allocator overhead and—for pooled—the retained other engine, this source-only bound cannot certify total RSS below 1 GiB. These are conservative ceilings, **not measured candidate counts or predictions that the fixtures attain them**.

Thus fixed-fixture arithmetic narrows the risk but does not fix the reviewed late-allocation guard or establish Mac capacity. The optional small CPU comparison is technically plausible with the existing bundle, but remains on hold. Any future run needs a fresh root scheduling decision, bounded failure cleanup, and the applicable reviewed package version. Its result would qualify only the direct Mac CPU path and exact public fixture; Linux Bubblewrap, Forge timing, CUDA/RTX 3070 behavior, and privacy results remain separate evidence.
