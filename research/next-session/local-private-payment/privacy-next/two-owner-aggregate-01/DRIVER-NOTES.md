# Aggregate driver: source-only review notes

`run.mjs` has no owner, signing, setup, proving, transaction or network mode.
Do not execute it before Root selects the complete source/run closure.

`prepare` creates exactly one fresh owned0700 tmpfs run, copies the immutable
public HANDOFF284a, derives the fixed 29 inputs, and writes their exact byte/hash
selection. It records the public projection and the plain constructor's known
mapping as an expected negative privacy control. Public owner-coded fixture
bytes make this **NON-PRIVATE**, regardless of private permutation wires.
Malformed negatives bypass host semantic validators; all public fields still
have canonical Fr integer encodings. No signing keys or fresh signatures exist.

`check` requires Root-selected CASE-SELECTION and COMPILED-SELECTION hashes.
The latter is a closed object with schema
`two-owner-aggregate-compiled-selection/v1` and five rows, each exactly
`{path,bytes,sha256}`:

| Row | Exact relative path |
| --- | --- |
| ordinaryR1cs | build-ordinary/aggregate.r1cs |
| cppR1cs | build-cpp/aggregate.r1cs |
| cppGenerator | build-cpp/aggregate_cpp/aggregate |
| cppData | build-cpp/aggregate_cpp/aggregate.dat |
| sym | build-ordinary/aggregate.sym |

Root's separately selected pipeline must generate ordinary `--O1 --r1cs --sym`
and official C++ `--O1 --r1cs --c --sanity_check 0 --no_asm` outputs from the
same source, then use the same exact selected make/G++/GMP dependencies as the
successful predicate CPP02. No generated-code patch or `NDEBUG` is permitted.
All builds/logs/witnesses stay in the selected tmpfs run. There is no compiler
or make invocation in this driver. No new package is requested.

Before witness generation, the driver requires full ordinary/CPP0 R1CS byte
identity; R1CS header has zero public outputs and exactly2091 public inputs;
all top-level `.sym` public names match the selected order; owner-data inputs
and each child's out35 are not aliased into public wires. Shared context aliases
inside children are retained in the audit report. `.sym` is a debug audit
artifact, not a native ABI or privacy proof.

Every one of the29 cases must produce a complete official C++ witness. Its
2091 public wire values must match the selected input before the unchanged
serial checker evaluates the ordinary R1CS. Generator/parser/checker failures
cannot count as a negative pass. Preserve the first unexpected input/witness
and stop. No automatic retry, rekey, retuning or acceptance fallback.
The first failure records guarded input-copy and witness pins, including any
regular empty/partial witness; pin errors remain separate from the failed
verdict. A used run is rejected without appending to its evidence. P07's replay
acceptance result is derived from its actual checked row, not from expectation.

The driver pins compiled inputs/checker before and after the trusted-host run.
It does not claim resilience to a concurrent hostile filesystem. Node's
resource counters exclude C++/compiler children; Root must capture their GNUtime
and apply the8GiB RAM/3GiB scratch/30CPU-minute outer envelope. Execution is
serial. Ordinary/CPP0 R1CS, positive witnesses and source/selection evidence are
retained; only successfully checked expected-negative witnesses are removed.

The relation still lacks CV algebra, encryption/CF hash/output-proof validity,
current accepted native state and replay database. P07 explicitly reaccepts the
same fictional state. No native, recovery, mapping-privacy, malicious-MPC or fee
qualification follows. The current native1NF→2CM design is untouched.
