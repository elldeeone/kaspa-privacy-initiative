# Two public v6 proofs in one nonsettling guest

This package implements the previously reviewed **binding-only** contract:
exactly two mode-1 zero-payout authorizations, a shared private anchor/count,
four distinct nullifiers, four complete sorted commitment/ciphertext records,
two index bijections, checked individual fees and their exact public sum.
Both Groth16 proofs are verified against the exact compiled research key using
the original two little-endian 128-bit authorization-digest limbs.

The canonical public projection is **1,088 bytes**. The journal is exactly
`KPI2V6J1 || u16le(1) || SHA256(projection)`: **42 bytes**. The guest receives
exactly 2,846 bytes and rejects trailing input. Its journal contains no
per-operation proof, digest, fee, anchor, index or grouping field. The entire
input remains visible to the collector/prover.

## Separate public development instance

The original rehearsal has no retained compatible pair. Its default `Gate`
still pins its original domain and VK. This experiment uses a **fresh,
single-party, untrusted, test-only setup** for the unchanged 4,372,824-constraint
v6 relation. The development public fixtures are preserved under
`evidence/public-development/`. No original setup, deployed covenant, user key,
live reserve or old pool state was changed.

The separate compiled instance is:

- Domain `d47cb91ef9ac74dda71c7db1519381526c3dfac5f525b904f744b97a7df713bd`.
- VK SHA-256 `2a9acd1639fb7b454384c65fb317a139695f5a2cbb3ebd941dd13b5f6045a2f4`.
- Public projection SHA-256 `9ac720aa55e7bd6eaec674788d418aa3314bc7af1010b7c9f09a493d9aa76ce9`.
- Journal SHA-256 `5d667b709f35191c6fc98e6aa0b79bd934e39a40ef4edfea582fcef3b06d4ac7`.
- Input SHA-256 `7771a2e610d37fdb12b1d668b8e229bd3cd1e5fe83c5993847daa0fef8c93b36`.

These identify public development evidence. They provide no historical-chain,
current-spentness, native-backing, payout, delivery, recovery or privacy claim.
This receipt must never authorize reserve release or another accepted spend.

## Shared relation and static parameters

The ordinary host and guest use the **same common crate** for parsing, profile
rules, sorting, multiplicity, bijections, fee arithmetic and P/J encoding.
The complete core was extracted from the independently reviewed host gate.
`ConfiguredResearchGate::with_trusted_key` remains fully checked for every key.

The optional, separately named `compiled::CompiledResearchGate` accepts no key,
digest or domain arguments. Its private key function refers only to immutable
compiled bytes. Before the guest is built, the host fully checks those exact
bytes: digest, checked canonical curve/subgroup decoding, complete consumption,
canonical re-encoding, nonidentity and three IC points. A separately frozen
source/key/tool/ELF/image record binds that preflight to the selected program.

Inside that selected guest only, repeated subgroup validation of the immutable
key is skipped using the established static-parameter optimization. Hash,
length, complete consumption, canonical roundtrip, arity and nonidentity remain
checked. Submitted proofs retain the unchanged helper's checked canonical
curve/subgroup decode, complete consumption, re-encoding and nonidentity checks.
The redundant higher-level proof decoder is omitted in the compiled route;
the actual proof verifier still performs all those checks once.

The original fully checked
[one-public-proof diagnostic](../v6-guest-compat/README.md) and its 84,842,708-cycle
result remain unchanged and separately identified. Its 40-byte journal is not
the two-proof contract journal.

## Build and qualify

Use the task-local official guest toolchain with its recorded archive hash,
SDK 3.0.3, Arkworks 0.5.0 and substrate-bn commit
`22108fe8c6ea1ebc1358fc4fd6854a6bf46e3509`. The host and guest locks retain
binfmt/zkp 3.0.4 and recursion 4.0.4 for the native compatibility check.

```sh
export CARGO_TARGET_DIR=/absolute/task-target
cargo +1.95.0 test --offline --locked --release --jobs 6 \
  --manifest-path poc/two-v6-binding/host/Cargo.toml
cargo +1.95.0 test --offline --locked --release --jobs 6 \
  --manifest-path poc/two-v6-binding/host/Cargo.toml -p kpi-two-v6-binding
cargo +1.95.0 build --offline --locked --release --jobs 6 \
  --manifest-path poc/two-v6-binding/host/Cargo.toml

# Mandatory checked static-parameter preflight BEFORE guest build.
/absolute/task-target/release/kpi-two-v6-binding-proof-host validate-key

RUSTC=/absolute/tools/risc0-rust/bin/rustc \
RISC0_FEATURE_bigint2=1 \
RUSTFLAGS='-C passes=lower-atomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings -C panic=abort --cfg getrandom_backend="custom"' \
  /absolute/tools/risc0-rust/bin/cargo build --offline --locked --release \
  --jobs 6 --target riscv32im-risc0-zkvm-elf \
  --manifest-path poc/two-v6-binding/guest/Cargo.toml
```

Wrap with the host's `wrap RAW_ELF NEW_PROGRAMS` command, then independently
review/freeze the exact build and expected image **before execution**. The host
checks its compiled image, program SHA-256, input SHA-256 and full expected P/J;
it never adopts an image returned by a prover or an adjacent metadata file.

Host tests compare the fully checked and compiled gates on the genuine new
pair, require identical P/J, check actual pairing rejection for altered
authorizations and reject malformed/identity proof points. Nine declared
mutations have exact reason-specific rejection checks.

Execution uses `execute PROGRAMS INPUT NEW_OUTPUT CASE`, with the local SDK
executor selected explicitly and development mode absent. It checks the exact
42-byte journal and `Halted(0)`. Resource/IPC failures never qualify as expected
rejection. Apply external cgroup/wall limits to every execution and proof run.

## Receipt route

`prove PROGRAMS INPUT NEW_OUTPUT` requests one real Succinct receipt and
durably saves a returned candidate before further checks. `verify RECEIPT
NEW_OUTPUT` runs separately and checks the official SDK proof, selected image,
exact journal, successful claim and no assumptions. It also reuses the existing
official seal-verifier callback to bind the decoded control to the independently
expected join control and official allowed-root inclusion. Negative controls
cover wrong image/journal, seal, inclusion and expected control.

The native journal argument is `SHA256(the actual 42-byte journal)`, not the
inner projection hash. Actual Kaspa precompile testing is a separate boundary;
a valid proof alone does not make the unchanged v6 covenant accept the new
public layout or authorize native settlement.

`evidence/build-freeze.json` records the source/build identity before execution.
Large programs, tools and runtime artifacts remain in the task target directory
with exact paths and hashes recorded in that manifest.

## Retained receipt compression and verification

The additive `compress_retained` binary accepts a saved Succinct receipt, its
independently frozen SHA-256 and a new output directory. It calls only the SDK's
compression API; it does not accept a guest ELF/input or execute the guest.
It requires the explicit IPC worker, authenticated existing RISC Zero Groth16
component files, a task-local work directory and an empty `GITHUB_TOKEN`.
Preserve the user's original HOME in a clean environment: Rzup requires it even
when RISC0_HOME explicitly selects the task-local component directory. Component
data stays read-only; only fresh scratch/output paths are writable.

The `verify_compressed RECEIPT NEW_OUTPUT` binary independently verifies a saved
Groth16 receipt against the compiled image, exact J and retained source claim,
and emits the complete matching P. It rejects fake receipts, a wrong image,
changed journal fields and a corrupted seal. It contains no proving API.

The successful Succinct packet, same-claim compressed packet, and the preserved
first initialization failure are in `evidence/succinct-receipt/`,
`evidence/groth16-receipt/`, and `evidence/compression-attempt-01/`. See
[measured results](RESULTS.md). These records supply a local proof and native
opcode compatibility result, not a settled batch or a privacy qualification.
