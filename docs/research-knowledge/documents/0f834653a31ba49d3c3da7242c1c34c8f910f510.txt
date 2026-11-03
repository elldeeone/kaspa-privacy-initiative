# Matched relation and parameter-runtime source review

**ACK for synthesis/constraint controls; setup gate remains pending actual controls.**
This is a source review of the new ADR-0057 implementation on2026-10-23 UTC,
not a proof of cryptographic correctness. No private inputs/PK blobs, build,
setup, proofs, native VM or network operation were used by this reviewer.

| New file | SHA256 reviewed |
| --- | --- |
| `poc/compact-batch-prover/src/lib.rs` | `10db2eb372df40e814b8ab85921898e7d3cac44eab2b6fe803a7dfbc5a455153` |
| `poc/compact-batch-prover/src/circuit.rs` | `34baa165b45dce138777971cbdb229403d7c770d86a6cddadf6bd01f35a95edb` |
| `poc/compact-batch-prover/src/request.rs` | `ce13ab1c54adeb2abc9f8e6bd95b62070ba2b4ac618276cab12d533e8cbd313c` |
| `poc/compact-batch-prover/src/exact_sha256.rs` | `24c7bb2e8c830261a1d000f96a0add5c19d7b992c1d7fcd0021ab272b0c0e9b8` |
| `poc/compact-batch-prover/src/main.rs` | `3a6c8e441316ad02cd92ee4063d0f3f243774d6a4332a34c07a4ef767189ceac` |
| `poc/compact-batch-prover/src/parameters.rs` | `d0558a12fc0882923758f5d521d6450879bc2ee8284d8bee153d1efa42e03acf` |
| `poc/compact-batch-prover/src/bin/setup.rs` | `8c79d54d434de67cf252e9d85421292c15f2b386b1869f746861881ccf27836c` |
| `poc/compact-batch-prover/build.rs` | `cf2eae949f9c145877480de750db0604092b6e6b95423790e98578056de15921` |

The exact SHA implementation is copied unchanged from the previously reviewed
relation. That reuse is not an independent cryptographic audit of the primitive.
The later lib.rs change from its initial15e57564 draft added only three public
encoding tests/rustfmt; production relation logic was unchanged.

## Constraint findings

No blocking source defect was found. Role is trusted fixed-shape construction;
private requests cannot select it, output arity is exact, and only Role controls
host allocation branches. Compact mode0 iffR'=0 and mode2 iffcontinuing; wide
forcesmode32/P0/continuing. Every27 reserved byte is constrained zero.

Start has zero upper16bits and zero lowlog2(N)bits. A bounded log2(N)-bit delta
and nonnegative equality start=oldn+delta uniquely enforce aligned ceiling;
nextn=start+N is constrained and both cursor bounds are checked. Terminal
start0 and CMroot/count carry are separately constrained.

All ordered output Note commitments feed the full CM-array SHA256. Every one
of1/496 pairwise comparisons includes dummy slots; only terminal disables that
list/distinctness relation. All terminal Note168 bytes, including rho, are zero,
Auth digest/metadata are zero sentinels and ciphertext hash is SHA256(528 zeros).
The positive-private-output-or-payout gate remains. Exact nonnegative field
sums of bounded u64 values stay far below the scalar modulus; aggregate input
is constrained<=MAX/reserve and equals every output+payout+fee. Host public
reserve subtraction is checked, with no wrapping sum substituted into a proof.

Input secret commitments, current16-level membership, distinct real positions,
canonical private dummy inputs, both nonzero/distinct NFs and actual-slot HMAC
formulas are preserved. Original real NF uses D/CM/physicalposition and no role
or mode; retained native REVEAL uses the same formula. Public input binding is
all SHA256(Auth528) split into exact LE128 limbs. Native context, NF absence,
tree/cipher transitions, payouts/fees and immutable code remain separate and
mandatory; the private relation does not assert acceptance of supplied state.

## Runtime findings

Compiled role-specific selection binds schema, D/genesis/profile/magic/arity,
source/build/matrix/dimensions/FFTdomain, exact VK and full public PK length/SHA.
The only trusted-input decoder consumes a completely authenticated owned byte
buffer, checks exhaustion, extracted canonical VK and query dimensions. READY
is flushed before opening the inherited private witness FD. Parser/panic errors
are fixed codes without witness values/paths/hashes. Output proof/Auth data are
created only after checked proof verification; raw unbroadcast alternatives
remain private under the separate publication rule.

Shape fingerprints contain finalized coefficient/variable-index/label/dimension
matrices, not assignments or witness hashes. Setup releases the retained CS
before official PK serialization and verifies the newly fsynced artifact by
its own descriptor. Operational memory fit, actual dimensions and matrix equality
remain measurements to obtain; source inspection cannot substitute for them.

## Remaining setup gates and adversarial boundaries

Before setup, require actual compact terminal/continuing matrix identity,
wide positive satisfaction, coherent last-slot31/order/duplicate/overflow,
mode/reserved/start and terminal rho/hash direct-constraint rejections. Parser
rejection must not stand in for UNSAT. Tiny loader controls must cover wrong
role/source/D/VK/dimensions and corrupted/truncated/trailing public artifacts
before witness reads; actual role PK reload belongs after fresh setup.

A strict singleton GN bootstrap is also required: ordinary funding Full checks
its P2PK input, not correctness of an arbitrary output state. Lifecycle has
acknowledged validating n1/m1, singleton CM/sentinel NF, payload/D/VKs and
Note.value==actual reserve before trusting a new history. Initial liabilities
cannot be justified by per-spend sumIn<=R alone.

The eight project risk questions remain explicit: exact conservation counters
inflation; shared NFs/native absence counter double spending; actual native
context/SPK/fee checks counter unauthorized release; public modes/amounts/timing
still leak information; missing public data/parameters reduce liveness; stale/
reorg evidence must fail closed; trusted setup/local host/software/selected node
history remain assumptions; and recipient decryption/rederivation/CM checks,
not ciphertext hashing alone, establish tested recipient spendability.
