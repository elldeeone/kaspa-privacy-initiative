# Native Output matrix gate: frozen source/run contract

Status: SOURCE ONLY. No Cargo, compiler, executable, constraint run, setup or
proof has been run for this crate. Root source review, independent review and
a separate resource release must precede any commands below. Independent
accounting and the final DATA/audit/publication pipeline have priority.

## Exact baseline and lift

The dependency is the unchanged local-payment native relation, source closure
82cf9c59c17c006f79faf2b7689d09690ad505b776f9ce6409f4d1f9ccc79e5c.
The public fixture comes from its existing circuit::fixture().1. Reconstructing
the existing deterministic public Pedersen parameters is allowed; generating
new Groth16 parameters/keys or reading a PK body is not.

- Field: BN254 Fr, modulus
  21888242871839275222246405745257275088548364400416034343698204186575808495617.
- Original: 217,807 constraints, three instances including ONE, 214,998 private
  fields; exact native matrix fingerprint
  21e21c057dc22d0100d2dd46a6867acba2f89ef1481b8046b4b8c29d8521c116.
- Public CV parameter-powers digest:
  401abafb0b375aa71159c6f4fff4002985f02a29acf0dfe03d89991734d3eeef.
- Require the complete predicate-label set to contain only R1CS, with exactly
  three matrices, exact dimensions and every column in bounds. No predicate or
  matrix is silently dropped.
- Wire map: original0→new0; original1→new3; original2→new4;
  original i>=3→new i+2. New0 is ONE; new1/2 are external digest limbs;
  new3/4 are internal digest limbs. New5 onward preserves the old private order.
- Append rows 217807/217808, zero-based:
  (internal[j]−external[j])*ONE=0. Lifted dimensions: 217,809 constraints,
  three instances and 215,000 private fields. Verify inverse remapping recovers
  every original coefficient/index/row exactly.
- Preserve the current byte/SHA/range/CV predicate. This does not refactor or
  modify any native source, statement, parameter, financial profile or key.

The second valid fixture changes only Note.value by +1 sompi, recomputing its
CM and CV through existing native helpers. It must have the same native matrix
identity and a different digest. A degenerate equality or fixture synthesis
failure stops; there is no seed/amount retuning to obtain the expected result.
Valid here means satisfying the current Output predicate. Its CFhash is bound,
but sealed-box correctness and recipient spendability are not checked.

## Fifteen prospective controls

Native baseline generation must pass both the native CS check and explicit
original A*z * B*z=C*z evaluation. Every semantic control evaluates all 217,809
lifted rows. Native-prefix and appended-link failures are reported separately.

| ID | Assignment | Expected result |
| --- | --- | --- |
| P01 | Original valid native fixture, equal external/internal limbs | SAT |
| P02 | Valid +1-sompi fixture, matching new external limbs | SAT |
| N01 | External low limb +1, all native/internal values fixed | Actual residual UNSAT; native prefix passes; first failure row217807 |
| N02 | External high limb +1, all native/internal values fixed | Actual residual UNSAT; native prefix passes; first failure row217808 |
| N03 | Coherent valid alternate native assignment with old external limbs | Actual residual UNSAT; native prefix passes; appended link fails |
| N04 | First original private field (new5) +1 | Actual residual UNSAT in native prefix; link rows pass |
| N05 | Both external/internal low limbs +1, native witness fixed | Actual residual UNSAT in native SHA predicate; link rows pass |
| N06 | Both external/internal high limbs +1, native witness fixed | Actual residual UNSAT in native SHA predicate; link rows pass |
| B01 | All-zero vector | ONE_NOT_ONE boundary refusal; zero rows evaluated |
| B02 | Constant wire2 | ONE_NOT_ONE boundary refusal; zero rows evaluated |
| B03 | Missing final assignment field | ASSIGNMENT_LENGTH boundary refusal |
| B04 | Extra assignment field | ASSIGNMENT_LENGTH boundary refusal |
| G01 | Tiny source-map fixture with extra empty predicate | PREDICATE_SET source refusal |
| G02 | Tiny source-map fixture missing C | MATRIX_ARITY source refusal |
| G03 | Tiny source-map fixture with out-of-range column | COLUMN_INDEX source refusal |

The four assignment and three source-boundary refusals are not counted as
constraint rejections. The three G controls exercise metadata admission with
tiny public fixtures, not native cryptographic negatives. Expected totals:
15 controls = two SAT, six actual residual UNSAT, four assignment refusals,
three source-matrix refusals. Unexpected results stop immediately after their
CONTROL event is emitted; no later PASS or permissive fallback is allowed.

## Dependencies and proposed closed commands

Cargo.toml uses exact versions. Cargo.lock is an additive derivative of the
native lock: all 153 original package records remain exact and one new path
package is added. The native crate remains a read-only path dependency. No
taceo/co-Groth16 prover is linked or executed; this first gate checks matrix
semantics only. It selects no R1CS-to-QAP reduction. Future proof work must bind
the exact key/reduction and cannot infer interoperability from this gate.

Toolchain selection: installed Rust1.97.1, metadata version
1.97.1 (8bab26f4f 2026-07-14), channel-manifest SHA
09cbf0ad7b7e084e3bf1131c6bd970ad34c29c9fcdc8db1f7836463b7322e69a.
This metadata was read, not a version command executed. A future build uses its
actual /home/luke/.rustup/toolchains/1.97.1-x86_64-unknown-linux-gnu binaries.

Before a future build Root must authenticate SOURCE-FREEZE-01 and all listed
native/dependency inputs through unchanged helper09, create a fresh owned0700
build directory under /dev/shm/kpi-native-output-matrix-gate-01, and qualify
adequate actual space/memory. No current-private directory, backup, PK,
credentials file or network interface is a build/runtime input. No new download
or global Cargo install/update is authorized. Missing offline sources stop.

Proposed build command inside a closed bwrap namespace:

    /toolchain/bin/cargo build --offline --locked --release --jobs 1 --manifest-path /src/research/next-session/local-private-payment/privacy-next/direct-native-composition-01/output-matrix-gate-01/Cargo.toml

The build namespace has network/PID isolation and cleared environment. It mounts
only the owned crate at that path, the eleven explicitly listed native source
files beneath /src/poc/local-private-payment/relation, Rust1.97.1 at /toolchain, ordinary
system compiler/libraries, and public Cargo registry/index/cache read-only at
/work/cargo/registry. It excludes host /home and /var outside those explicit
public mounts. /work is a new owned writable build directory; CARGO_HOME is
/work/cargo, CARGO_TARGET_DIR is /work/target, RUSTC is
/toolchain/bin/rustc, PATH is /toolchain/bin:/usr/bin:/bin, CARGO_NET_OFFLINE=true,
CARGO_BUILD_JOBS=1 and RAYON_NUM_THREADS=2. The outer context must remain normal
if a user-service scope is used; clear the child environment after service
creation. Capture exact selected argv, stdout/stderr, time, status and artifacts
only for this explicitly public synthetic process, never another live process.

Proposed runtime command in a separate closed bwrap namespace:

    /probe --output /out

Mount only the authenticated built binary at /probe, necessary ordinary system
libraries, fresh owned empty output at /out, and fresh /tmp, /proc and /dev.
Clear environment; network and host/home/private/repo/PK inputs are absent.
Do not mount the native crate or build registry at runtime. No stdin input is
accepted. Optional resource scope: nice10, at most two CPUs, MemoryMax4GB;
release it only with at least8GB actual host headroom and after heavier current
accounting/cold scans. These are prospective optional-probe limits, not limits
on the financial trial. Root can select a more generous envelope prospectively.

The SOURCE-ONLY task does not execute these commands or create runtime dirs.
COMMANDS-01.json records the exact proposed bwrap argv and fresh paths. Root
must select/authenticate those commands and any outer resource scope before
any run; this plan is not an execution wrapper or a hidden run release.

## Evidence and stop rules

The program emits BASELINE, one CONTROL per outcome and one final summary only
after all15 match. It exclusively creates four ordinary0400 public artifacts:
ORIGINAL-MATRICES.bin, LIFTED-MATRICES.bin, PUBLIC-BASE-ASSIGNMENT.bin and
PUBLIC-ALT-ASSIGNMENT.bin. These are synthetic data, kept outside Git/release.
Every mutation is an explicit delta or baseline-selection descriptor in stdout;
it can be reconstructed from the retained baselines without fifteen full copies.

Matrix format is a local evidence format, not snarkjs .r1cs: magicKPIOMAT1,
u64LE(instance,witness,constraint counts), then three matrices, each with
u64LE row count and each row with u64LE term count followed by canonical
Arkworks Fr32 and u64LE column pairs. Assignment format: magicKPIOASN1,
u64LE count, then canonical Fr32 values. The program streams bodies and hashes;
Root must independently helper09-check the resulting ordinary file identities,
lengths and digests. No post-hoc format correction or replaced original is allowed.

Preserve compile failures, source refusals, all prior emitted controls and the
first unexpected result. Do not override checks, silently change dependency
versions, retune the fixtures, generate keys/proofs or retry a used run identity.
A source correction gets new prospective source/freeze/run identities.

PASS would establish this synthetic Output/matrix interface only. It would not
qualify six native components, private bijections, spending authorization,
MPC/malicious witness generation, proof interoperability, native2/4 execution,
encryption/delivery, recovery, fee savings, anonymity or production security.

