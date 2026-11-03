# Signature component source bridge

2026-10-27. Source preparation only. The adapter has not been imported,
syntax-checked, built or executed. No signature, witness, constraint check,
setup, proof, key generation, MPC, RPC, financial or private job ran.
This directory is isolated outside the repository/publication candidate.

`signature-component-adapter-01.mjs` implements format admission and canonical
wire relabeling, not signature acceptance. It adds no cryptographic primitive.
No body read, path input, filesystem output, subprocess, network call, dependency
resolution or generator is present. Every input body must first be admitted by
unchanged helper09 in a separately reviewed runner. Every output later written
to disk must be helper09-admitted and hashed again before Rust consumes it.

## Exact APIs and dependency boundary

Inject these authenticated, already installed existing APIs:

1. `readR1cs` from r1csfile0.0.48's selected `src/r1csfile.js`.
2. The default `F1Field` constructor from its nested ffjavascript0.3.0
   `src/f1field.js`, not a signer field or a different nested package version.
3. The default export of snarkjs0.7.6 `src/wtns_export_json.js`, exposed as
   `exportWitnessJson`. This is the implementation of stock `wtns.exportJson`.

The adapter calls `readR1cs(Uint8Array, {F,loadConstraints:true,loadMap:true,
loadCustomGates:false,singleThread:true})` only after strict raw preflight.
Supplying F1Field avoids implicit curve/WASM construction. The selected
fastfile0.0.20 source explicitly accepts Uint8Array through its memory-file
path; both library APIs therefore receive a fresh snapshot and no filename.
This exact memory route was source-inspected, not run. Its fastfile and F1Field
sources were compared with authenticated locked official npm archives; new pins
are in API-SOURCE-PINS-01.json. Prior pinned format/source ledger identifies
r1csfile/snarkjs/binfileutils sources and archive parity. Full transitive
dependency/source-lock authentication remains the future runner's prerequisite.

No imports occurred during preparation, including Node's built-in crypto.
The source contains the intended future crypto import solely for SHA256 artifact
identity, not as a replacement for any circuit hash or predicate.

## Two-stage interface

`prepareSignatureMatrix(input,deps)` accepts three helper09-admitted Uint8Array
bodies: `ordinaryR1cs`, `cpp0R1cs`, `symBytes`. `input.pins` contains those exact
three keys, each with canonical lowercase `sha256` and integer `byteLength`.
All buffers are snapshotted and checked. Full ordinary/CPP0 byte identity is
required before parsing or the common normalization.

The result has `matrix`, `mapping`, `metadata` artifacts. Each has `bytes`
(the exact future file body), `byteLength`, `sha256`. The matrix routine also
retains a private same-process context in a WeakMap. Its row/permutation state
cannot be supplied as a host object to the witness routine. Artifacts may be
inspected/written by the future reviewed runner; changing matrix/mapping bytes
will be refused before witness export. This API is not a serialized-context
loader: after process restart rerun matrix preparation with the same admitted
inputs, compare its pins and then supply the already frozen map/matrix hashes.

Before any witness/control, freeze `mapping.sha256`, `matrix.sha256`, actual
dimensions and source/tool build identity. This is a future post-build step;
no actual map exists yet. Do not choose/revise the mapping after a control.

`prepareSignatureWitness(input,prepared,deps)` accepts `wtns` Uint8Array,
`pin:{sha256,byteLength}` and `frozen:{mappingSha256,
normalizedMatrixSha256}`. It requires a successful same-process matrix result
and both exact previously frozen hashes. The result has `witness` and
`metadata` artifacts of the same shape. The routine checks every stock
snarkjs-exported value against the strict raw witness vector before relabeling.

There is deliberately no CLI or capture/loader/writer wrapper. Those belong to
the parent's frozen closed-runtime commands and are not silently qualified by
this module. API examples here are contract prose, not execution release.

## Raw admission before library conversion

- Exactly R1CSv1 sections1/2/3 and WTNSv2 sections1/2, each once, with exact
  magic, section count, uint64 lengths, fully consumed contents and EOF.
  Either custom section4 or5, any other section, missing/duplicate section,
  extra bytes or a non-exact version stops. No supported-predicate omission.
- Width32, exact BN254 Fr modulus, zero outputs,66 public inputs, nVars>=67,
  nonempty ordinary relation. Full private/aux count is nVars-67, independent
  of nPrvInputs. nPrvInputs is retained as declared-input metadata only.
- Every raw coefficient/value is read as unsigned LE integer and checked<P
  before any field conversion. Every wire index<nVars; duplicate encoded
  wire terms refused even if a library would overwrite them. Zero coefficients,
  raw LC term ordering and every A/B/C row are retained.
- Wire-to-label map is exactly8*nVars bytes; all labels are distinct, in range,
  and label0 remains at ONE0. uint64 labels/nLabels above MAX_SAFE_INTEGER are
  explicitly unsupported because the selected library uses JS Number there.
  They are refused before library parsing, not rounded through Number.
- Witness count and values section exactly nVars and32*nVars, not only declared
  private inputs. Raw wire0 must equal integer1. Noncanonical encodings, ONE0,
  truncations and malformed shapes are assignment/format refusals, never UNSAT.

After preflight, compare every library header, map value, row, LC term count and
coefficient with raw data. Constraint term matching ignores only object-key
enumeration order; export retains actual raw term order. No duplicate merging,
coefficient reduction, row sorting, zero dropping or custom-gate fallback.

## Frozen normalization

Only these exact66 names are selected, in this canonical order:
`main.digestLimbs[0]`, `main.digestLimbs[1]`, then
`main.ownerKeyBytes[0]` through `[63]`.

Parse the second .sym CSV column as physical wire index, not original label or
component ID. Require a bijection onto every raw public wire1..66, no -1/missing
or duplicate selected signal, and zero outputs. The full .sym must also cover
every nonzero physical wire once with the matching original wire-to-label ID;
optimized-away rows may have -1. ASCII/LF .sym only; CRLF, non-ASCII or malformed
records are explicitly unsupported rather than normalized silently.

Derive raw->canonical and canonical->raw permutations solely from those names.
ONE0 stays0; all raw private/aux wires>=67 stay fixed. Relabel every A/B/C term
and map label, and permute every witness value identically. Inverse-check every
permutation entry, row, term, coefficient, label and assignment entry. No source
declaration-order inference. The map artifact records all66 public mappings and
the fixed suffix rule; matrix/witness artifacts bind its hash.

The 64 component-public key bytes remain internal in the proposed parent join.
Parent retains separate component copies and appends68 actual equality rows:
2 Native SHA->outer,2 signature SHA->outer,64 key-byte links. This adapter does
not create those rows, prove their visibility, evaluate residuals, or collapse
component wires. The joined proof/key boundary remains entirely new.

## Plain interchange for the Rust join

Artifact bodies are UTF8 JSON, recursively sorted object keys, arrays in exact
order, no spacing, final LF. No BigInt JSON or JS floating point field values.
All Fr coefficients/values and uint64 labels are canonical unsigned decimal
strings. Wire indices, counts and dimensions are exact nonnegative JSON integers.

Matrix schema `kpi-signature-normalized-r1cs/v1` includes field, n8, nVars,
nInstances67, nWitnesses=nVars-67, nOutputs0, nPublicInputs66,
nDeclaredPrivateInputs, nLabels, nConstraints, rows, wireToLabel and mappingSha256.
Each row is `[A,B,C]`; each LC is an ordered array of `[wire,coefficientString]`.
The Rust importer must preserve every row/term, recheck all index/shape/field
invariants and use exact Fr conversion; it is still parent's implementation.

Witness schema `kpi-signature-normalized-witness/v1` includes field, nVars,
nInstances67, nWitnesses=nVars-67, mappingSha256, normalizedMatrixSha256 and
the complete normalized `values` vector. `values[0]` is `"1"`.

Each metadata artifact has its own returned byteLength/SHA256. These hashes bind
the exact generated metadata bytes. Matrix, mapping and witness hashes must be
recorded/rechecked in the parent's independent admission, not trusted as fields
inside arbitrary edited JSON. No R1CS setup/key reuse follows from any hash.

## Refusal and test boundary

Every intentional admission refusal uses BridgeRefusal with a distinct code
and kind FORMAT_OR_INTERFACE_REFUSAL_NOT_R1CS_UNSAT. Library failures are
wrapped as LIBRARY_REFUSAL with the original cause retained. Any unexpected JS
exception also stops the future run; do not catch it as success, synthesize a
partial witness, alter parsing or retry the used identity. There is no fallback.

This adapter intentionally permits canonical-Fr semantic bad inputs such as
byte256, an out-of128-bit limb or S=Q to reach the actual selected predicates.
It does not verify a host valid flag or call a signature verifier. The parent
must separately obtain complete recomputed CPP0 witnesses and traverse actual
joined A*z*B*z-C*z rows, including coherent stale-signature/re-signed controls.
Parser, generator, ONE/shape, source-map and actual residual outcomes stay separate.

No test or compatibility claim is completed. Still required before execution:
independent source review; actual source/lock/tool admission and closed runner;
exact post-build dimensions/map freeze; finite successful/negative raw-format
controls; Rust schema agreement; full joined residual controls. Main pipeline
and available memory retain priority. No NativeBatch, MPC, privacy, fee,
recovery, independent Exit or current-profile acceptance is inferred.
