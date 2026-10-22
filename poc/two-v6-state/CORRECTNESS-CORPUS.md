# Frozen public correctness corpus

The corpus contains **128 distinct supplied synthetic context inputs/J336** and
**35 invalid inputs**. It reuses the unchanged genuine development pair/P.
It tests local context/path correctness only: no accepted genesis, backing,
reachability, native reserve, owner exit, privacy or chain claim is made.
The original two independent fixtures and their manifest remain unchanged.

The public deterministic seed is exact ASCII
`KPI/public-two-v6-state/correctness-corpus/v1`. The frozen plan precedes Rust
execution and is not a hidden evaluation seed or a privacy experiment.

| Frozen item | SHA256 |
| --- | --- |
| `public_correctness_corpus.py` | `e4ef6d7a3598df471e561f5c37df458d3b5fc7e02711c6dea67319567ab33be6` |
| `correctness-corpus-plan.json` | `08183d20e6c15fa4591ebd903d5e133d4e3afaf5fa035e465f6f2d956deefe96` |
| Generated `public-corpus/manifest.json` | `19fc246c682a9545da41bec205535a6c76b6207dd05fdbf98ccf2fe1c9a74e6f` |

Output root:
`artifacts/public-state-correctness-corpus-20261022T132924Z/`.
Each `public-corpus/valid-NNN/` contains exact `input.bin` and independently
expected `expected-journal.bin`. The manifest includes prior/next states,
intermediate NF/CM/history roots, dimensions and file hashes. Negative inputs
are under `public-corpus/negative/` with frozen expected error families.

The 128 positives form the full fixed product:

1. Prior CM counts 3, 5, 17 and 65,531, retaining the genuine count-3 anchor.
2. Eight NF shapes: sentinel, tail, first/last/all bracketing, hashed public
   values, numeric neighbors, and high count near the valid capacity boundary.
3. Numeric and deterministic permuted physical indices. The indexed ordering
   remains little-endian numeric; genuine public P remains raw-byte sorted.
4. Reserve F+1 and MAX_SOMPI, with the genuine aggregate fee fixed at 80M sompi.

Prior even NF counts range from 2 through 131,060; CM65,531 appends to65,535.
All 128 input and journal hashes are distinct. Their public CM/history vectors
are internally consistent, and every indexed NF list is constructed with a
sentinel, unique nonzero values and correct ordered links. This says nothing
about whether such a predecessor arose through accepted operations.

There are 33 semantic/binding negatives and two framing negatives. They cover
state counts/version, initialization, capacity, count/anchor membership,
current-root consistency, NF index/order/link/root/empty-slot predicates,
CM/history paths, reserve underflow/range and P/bundle binding. In particular,
`nf-authenticated-replay/input.bin` puts the actual first public NF in the
declared current tree and supplies its correct existing-leaf authentication
path. Equality fails strict NF ordering, expected `NullifierOrder(0)`;
the input SHA256 is
`0b8a4cb2adc1301eb176f48773c0db27a8c68bcdb345c316e5e24c04468345ca`.
It is not a stale-path rejection. The unused append path is irrelevant after
the strict equality failure.

The genuine unchanged proof pair fixes F. Consequently modified P fee bytes
must fail **Binding**, before the state's Fee guard; the corpus does not claim
that unchanged genuine proofs can reach an arbitrary fee or u128 value.
Resource/process failures are separate failures, never semantic evidence.
Keep every differential mismatch and do not tune or remove cases after seeing
Rust outcomes.

Independent source review found one expected-family defect before Rust:
`nf-equality-wire` violates the sentinel link rule before reaching ordering,
so source predicts `NullifierLink(0)` while the frozen plan says
`NullifierOrder(0)`. The original source/plan/corpus are preserved. The additive
`PRE-RUST-EXPECTATION-ERRATUM.md` in the output root records the reason and
identities; differential must retain and report the original mismatch. The
separate authenticated existing-NF replay retains its correct Order expectation.

The generation unit was `kpi-public-state-corpus-20261022t132924z.service`,
MainPID1635893, started13:29:24UTC and exited13:29:29UTC on2026-10-22. Its
hard deadline was13:49:24UTC. Enforced caps were6CPU,4GiB RAM,zero swap and20min;
bubblewrap isolated the network, made source/root read-only and exposed only
the new artifact directory writable. Actual CPU was4.949024seconds and cgroup
memory peak94,773,248bytes. All generated sizes/hashes were rechecked. Retained
launch/terminal/cleanup records show exit0, inactive/dead unit, MainPID0 and
empty ControlGroup. No Rust/native build, guest execution, setup or proof was
run in this generation step. Root releases differential execution separately.
