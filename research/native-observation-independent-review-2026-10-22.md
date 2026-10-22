# Independent public-native observation review — 2026-10-22

**Result:** one typed-output integrity defect was reproduced, corrected by the
implementer and independently rechecked. No unresolved blocking defect was found
in the reviewed Python projection or prepared native integration. Native Rust
execution was pending at the source-review checkpoint; the later lane result is
recorded separately below.

## Reviewed scope

The additive files in `../native/poc/shared-pool/` are
`public_native_observation.py`, `public_native_observation_tests.py`,
`verify_public_native_observation.py`,
`src/bin/kpi-public-native-observation-check.rs` and
`PUBLIC-NATIVE-OBSERVATION.md`. The integration wrapper's actual filename is
`verify_public_native_observation.py`.

The unchanged source baseline is
`ec6aa15d586bcc8a90f7232b433fd48d8c73d509`; native dependencies remain pinned to
`01b532e8b553523216471682649693af92f0fd16`. Source comparison covered v6
authorization layout, commitment/history/indexed-nullifier trees, settlement
witness construction, canonical native parsing and offline replay. No private
evidence, evaluation inputs, keys, setup or prover parameters were accessed.

## Fixed finding: equality did not preserve output types

The first `validate_observation` implementation compared Python dictionaries
with `==`. That accepts `True == 1`, `False == 0` and `0.0 == 0`. Against the
retained public fixture, replacing the first record's `mode=1` with `True`, or
`ordinal=0` with `False`, still validated even though canonical JSON bytes
differed. This affected the new claimed-output validation boundary; the native
input parser's integer checks were already strict.

The implementer changed validation to compare canonical JSON bytes against the
regenerated projection. JSON encoding now rejects NaN. Controls include Boolean
mode, Boolean/float ordinal, integer verification flags and NaN. Independent
recheck confirms the three original typed substitutions reject, and the updated
20-test suite passes. No source in the implementation worktree was edited by
this reviewer.

## Independent checks

The final Python suite passed all **20 tests** in 0.574 seconds in this review,
using `PYTHONDONTWRITEBYTECODE=1`. The earlier 17-test version also passed before
the additional integrity/ancestry controls; that result is not substituted for
the final source identity.

The separate reviewer script,
[native_observation_independent_checks.py](native_observation_independent_checks.py),
uses only the three hash-pinned public rehearsal fixtures. Its own SHA-256 path
fold does not call the adapter's `PublicTree` or `PublicState` methods. Across
all 13 operations it independently folds **132 paths** and checks **98 root
equalities**:

- Historical anchor inclusion into the preceding history root.
- Each indexed-nullifier predecessor, its updated leaf, empty append position
  and sequential new nullifier root.
- Empty commitment append positions, both appended commitments, and old/new
  history roots.

All checks pass, along with three typed-output rejection controls. The script
does not independently verify private relations or native execution; it checks
public Merkle path closure against the preceding supplied script state and the
adapter's recomputed next state.

The [retained result receipt](native-observation-independent-checks.json) pins
the reviewer script and implementation source hashes before/after execution,
the exact command and its public-only scope. Its SHA-256 is
`d2de5ed699c73957f5bece64627ebfa9e9ff01ca0e7e5aaa4dd61efecc5bc315`.

Reproduction from the integration worktree:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/native_observation_independent_checks.py
```

## Source-contract conclusions

| Boundary | Review conclusion |
| --- | --- |
| Integer amounts and indices | Input parsing requires exact integers or canonical decimal strings; rejects bools/floats and out-of-range values. Individual native amounts are bounded; cumulative turnover remains an integer with an explicitly different aggregate range. |
| Prefix selection | The selected lineage is cut before later bodies are parsed. Only directly consumed parent bodies enter the selected snapshot. Full parent bodies preserve public sibling outputs; unselected parents are excluded. The final suite covers all 14 cuts and poisoned later inputs. |
| Roots and witness bytes | Leaf tags, little-endian counts/indices, little-endian nullifier ordering, 16/17-level depths, sequential NF insertion and commitment/history append offsets match the unchanged Rust source. All 4,368 witness bytes are regenerated and compared. |
| Descriptor identity | Python requires an external expected descriptor digest, matches canonical descriptor bytes to it and checks VK identity. The fixed fixture wrapper supplies a separately hardcoded known digest; callers remain responsible for authenticating its source. A self-chosen digest is not external authentication. |
| Native IDs and full hashes | Standalone Python deliberately does not recompute them. The prepared Rust path uses the existing canonical native parser, checks founding ID/full hash against the descriptor and computes lineage full hashes. The wrapper compares all 14 pool-lineage IDs/full hashes to the retained public receipt and checks the exact input-file digest. This implementation path was inspected, not executed in this review. |
| Funding ancestry | Selected parent outputs/outpoints are available context, not proof that those parents spent valid UTXOs. The explicit changed-parent-signature control is expected to remain accepted with `funding_parent_spends_verified=false`. Known public edges do not establish ownership or economic allocation. |
| Verification claims | Python leaves VM, proof, transaction-identity, canonical-covenant, parent-spend and chain-acceptance flags false. Native replay can establish the narrower first four under its supplied context; parent spending and accepted-chain authentication remain outside it. |

The native executable is a fixed retained-fixture control runner, not a generic
network observer. Its checks deliberately recompute mutated transaction IDs
before reaching proof/covenant checks, so stale-ID rejection cannot replace the
intended negative validation. The wrapper retains its independent Python output
and native result as separate artifacts rather than silently upgrading the
standalone projection's flags.

## Final reviewed source identities

SHA-256, relative to the native worktree's `poc/shared-pool/`:

```text
0ba861b4458b1fa4ca572b4d783c957ee7be39188c45982aced8565455d83c6e  public_native_observation.py
25b13a95a63b66898f289e58ca56fbc018f55484e80870f3e49dc2b5514db56b  public_native_observation_tests.py
d75ed39b29a0611ef4597e4531b517b402f9321697e327766fafb0a927969bfa  verify_public_native_observation.py
0321b3a2d57093b51a58d85bd24fbfb798d4a8ef648900abe615b9449689b869  src/bin/kpi-public-native-observation-check.rs
91f22bfa47c05e35bd477da73da308db162d642b611d8f75b232830aca4f95c0  PUBLIC-NATIVE-OBSERVATION.md
```

No Rust build, native VM/proof execution, network operation or funded action was
performed by this review. The remaining concrete validation step is the prepared
native cross-check under the coordinator's allocation. Successful execution
would establish its named historical-public-byte scope, not current chain
acceptance, privacy qualification, independent funding ancestry or production
security.

## Subsequent native execution artifact

The lane subsequently published
[attempt-01 validation](../../native/poc/shared-pool/evidence/2026-10-22-public-native-observation/attempt-01/validation.json).
This reviewer inspected its validation, native output and manifest and verified
all seven artifact hashes/sizes against that manifest. It records eight native
controls, 14 retained lineage IDs/full hashes, three native prefixes and complete
13-witness/root/accounting agreement. Parent input spending and chain acceptance
remain explicitly unverified. This is review of another lane's execution, not a
second independent execution.

The adapter, tests and Rust binary source hashes match the review checkpoint.
The integration wrapper additionally records Python test execution and expanded
source provenance; its executed SHA-256 is
`54ca4860c2c7ae09eb0bf4dd6a0e578e6d57818a2c16475ab15152903daf9266`.
The [live result register](intensive-2026-10-22/RESULTS.md) links the executed
binary and output identities; the pre-execution source table above remains the
historical review identity.
