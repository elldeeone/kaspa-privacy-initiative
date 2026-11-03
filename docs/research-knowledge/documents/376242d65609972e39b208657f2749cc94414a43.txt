# Signature-authority predicate: frozen small prototype plan

**2026-10-26 — plan only; Root decides implementation. No architecture selected.**

Test the actual RAILGUN/Circomlib authorization pattern with two unfunded
fictional owners, one input and two outputs each. Keep each independent signing
key in its owner process; give a plain prover the other material and signatures.
Compile one owner predicate and reuse it for A/B, without setup or proving keys.
**A satisfying witness is not a generated Groth16 proof.** Genuine proof
generation would require a separate later decision and resource/audit review.

This follows [source memo 01](COLLABORATIVE-INTENT-PROVING-SOURCE-01.md), SHA256
`5f8ccd7e1834be152dfba9ee88a78c73748026201946cd8d92fff98bddea9959`.
It selects no native profile, KDF, note format, exit rule or MPC construction.
The frozen 2% fee **FAIL**, active changed-cohort retry failure and final
25-file model closure remain unchanged. No current source or Original changes.

## Source and tool gate

Reuse [RAILGUN JoinSplit](https://github.com/Railgun-Privacy/circuits-v2/blob/0aa2d13763a9fcfbb7b7ea9c02e004e71f1394bb/src/library/joinsplit.circom#L37-L96)
for mandatory signature verification, signing-key/nullifying-key note binding,
nullifiers and output commitments. Its package pins Circomlib 2.0.5. Use that
exact [EdDSAPoseidonVerifier](https://github.com/iden3/circomlib/blob/cff5ab6288b55ef23602221694a6a38a0239dcc0/circuits/eddsaposeidon.circom),
file SHA256 `3e85c0aac26da6e8dd10565643790f82c905e88db0c5a673853e329618e1c29e`.
This is Baby-Jubjub EdDSA/Poseidon, not another EdDSA variant. No Rust/Go
signature substitution or handwritten replacement verifier is allowed here.

Metadata-only inventory of checked paths found:

| Resource | Observed availability; not a runtime check |
| --- | --- |
| Node/npm/npx | PATH entries under `/home/luke/.local/bin`; Node v24.15.0 directory exists. Wrappers were not executed. |
| Rust/Ark | Cargo/rustc paths exist; cached Ark 0.6.0 BN254, Edwards-on-BN254, Groth16, relations and R1CS sources. No checked repo release target. These are not the selected Circomlib signature toolchain. |
| Go | `/home/luke/.local/go/bin/go` exists; not needed for this gate. |
| Circom tooling | No `circom`, `circom2` or `snarkjs` on PATH. No repo `circomlib`, `circomlibjs` or `snarkjs` package. Checked global Node package directory also lacks them. |
| Public source cache | Selected RAILGUN/Circomlib files exist; not a complete transitive build/signing closure. |
| Disk | 2,963,189,760 free bytes at inventory; shared with the live trial and subject to change. |

Use explicit existing Node path
`/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node`,
Root-provided SHA256
`d1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c`.
Metadata confirms 122,889,056 bytes, mode 0500; it was not executed or rehashed
here. Do not assume `/usr/bin/node` or use a PATH wrapper for the prototype.

Propose these exact tools, subject to Root's selection; only release/registry
metadata and the linked source paths have been read, no packages/binary fetched:

- [Official Circom v2.2.3 Linux amd64 release](https://github.com/iden3/circom/releases/tag/v2.2.3):
  13,145,432 bytes; release SHA256
  `85342c7ff332d948df7c0c50ecf201e6129349aef550ce873f3c811b79fe53a3`.
  Tag source commit `ad44e915a12bb047b05745c2884aad9cc8326bc6`.
- [Circomlib 2.0.5](https://registry.npmjs.org/circomlib/2.0.5): gitHead is the
  selected `cff5ab6...` commit above; registry SHA512
  `O7NQ8OS+J4eshBuoy36z/TwQU0YHw8W3zxZcs4hVwpEll3e4hDm3mgkIPqItN8FDeLEKZFK3YeT/+k8TiLF3/A==`.
- [Circomlibjs 0.1.7](https://registry.npmjs.org/circomlibjs/0.1.7), gitHead
  `4f094c5be05c1f0210924a3ab204d8fd8da69f49`; registry SHA512
  `GRAUoAlKAsiiTa+PA725G9RmEmJJRc8tRFxw/zKktUxlQISGznT4hH4ESvW8FNTsrGg/nNd06sGP/Wlx0LUHVg==`.
  Its actual [`prv2pub`/`signPoseidon`](https://github.com/iden3/circomlibjs/blob/4f094c5be05c1f0210924a3ab204d8fd8da69f49/src/eddsa.js)
  use the selected Base8/cofactor/Poseidon convention. Inspected methods, not
  an entire dependency audit; RAILGUN's inspected tests merely consume vectors.
- [Snarkjs 0.7.6](https://registry.npmjs.org/snarkjs/0.7.6), gitHead
  `9a8f1c0083d18b9b5e18f526cfd729e7259423be`; registry SHA512
  `4uH1xA5JzVU5jaaWS2fXej3+RC6L5Erhr6INTJtUA27du4Elbh4VXCeeRjB4QiwL6N6y7SNKePw5prTxyEf4Zg==`.
  Its inspected [`wtns_check`](https://github.com/iden3/snarkjs/blob/9a8f1c0083d18b9b5e18f526cfd729e7259423be/src/wtns_check.js)
  evaluates every R1CS constraint; no proving API is needed.

Freeze the complete transitive package lock/integrities and included circuit
files before execution. Routine dependency setup follows Root's exact tool
selection, not a user permission request. No installation/build/download yet;
never run the whole RAILGUN build/ceremony or a compiler source build here.

## Frozen relation and fixture specification

Only public fictional records: owners A/B, leaf indices 0/1, a two-leaf tree,
two distinct input NFs, four output commitments. No actual ledger input.
Each owner has **2,000,000,000 sompi in; 100,000,000 payment;
1,890,000,000 change; 10,000,000 fee**. These are test constants, not measured
native fees. Input/output/fee integers receive 64-bit range constraints;
`input = payment + change + fee` is constrained without field wrap.
Use test/chain/pool/profile/role/asset tags `1/101001/201001/301001/401001/601001`;
owner index `i=0,1`, nonce `501001+i`, nullifying key `800001+i`, input random
`700001+i`, payment/change NPK `900001+2*i+j` (`j=0,1`). Heights are
`validFrom=100`, `validUntil=200`, `evaluationHeight=150`. Non-CM tuple byte
at offset k is `(17*k + 29*j + 41*i) mod 256`; keys/signatures and derived
commitments/root are generated later by the frozen recipe, not chosen to pass.

For each owner, adopt the exact source pattern:

```
masterPK = Poseidon(PK.x, PK.y, nullifyingKey)
inputNPK = Poseidon(masterPK, inputRandom)
inputCM  = Poseidon(inputNPK, syntheticAssetTag, inputSompi)
NF       = Poseidon(nullifyingKey, leafIndex)
outputCM[j] = Poseidon(outputNPK[j], syntheticAssetTag, outputSompi[j])
anchor = Poseidon(inputCM[A], inputCM[B])
```

Constrain each owner's depth-one membership/index against the same public
anchor. Distinct A/B NFs are a fixture invariant, **not an aggregate circuit
check**. The synthetic asset/domain tags are separate test constants, with no
current KAS profile/domain interpretation. The separate signing secret is
neither a witness nor derivable from shared nullifying material by this design.
Today's `owner_secret` must never be supplied to the prover or relabelled.

The signed message retains RAILGUN's one-input/two-output structure:

```
M = Poseidon(anchor, B, NF, paymentCM, changeCM)
B = Poseidon(testTag, chainId, poolId, profileId, roleId, nonce,
             validFrom, validUntil, feeSompi, Xlo, Xhi, outputCount=2)
```

All tags/IDs are frozen small field integers; nonce and heights are 64-bit
integers. `evaluationHeight` is public, range constrained, and must lie in the
signed inclusive interval. Anchor policy is **this exact root only**. Head/root
movement requires another signature; no current-chain oracle, accepted-state
reservation, replay database or durable head-evolution policy is implemented.
Rechecking the same intent at the same eligible fictional state is allowed.
Cross-pool/profile/role/nonce changes must fail with the old signature.

`X = SHA256(ASCII("KPIAUT01") || tuple[0] || tuple[1])`, split into two unsigned
128-bit little-endian limbs, never reduced modulo the circuit field. Each
test tuple has this fixed order and length:

```
CM32 || CV64 || CF264 || ciphertextHash32 || consistencyProof128   (520 bytes)
```

The CM bytes canonically encode the corresponding output field commitment.
All bytes, including every CF byte and both proof/value-commitment fields, are
included; output order is signed. The other fields are explicitly fictional
bytes, not claimed valid current output encryption/consistency proofs.
The byte positions follow the public [current wire parser](../../../../poc/local-private-payment/verification/common/src/wire.rs#L119-L127),
SHA256 `136f7b1115a64d08e9789114be04d0fa3de90b05da5aa2216bd686effc7b6562`;
its CF is 264 bytes, not Receipt216. This does not make the synthetic note,
commitments, ciphertexts or statements compatible with the current profile.

Use pinned Circomlib [`Sha256(8384)`](https://github.com/iden3/circomlib/blob/cff5ab6288b55ef23602221694a6a38a0239dcc0/circuits/sha256/sha256.circom)
over the actual 1,048 bytes: `Num2Bits(8)` for every byte; feed each byte's bits
MSB first. Constrain CM bytes to their corresponding strict canonical field
decomposition. Convert its 256 output bits to digest bytes, then constrain
`Xlo = LE128(digest[0..16])`, `Xhi = LE128(digest[16..32])`. No modular
reduction or host-supplied digest. The [pinned upstream tests](https://github.com/iden3/circomlib/blob/cff5ab6288b55ef23602221694a6a38a0239dcc0/test/sha256.js)
and compression output wiring document bit order. Compare all 32 bytes to
Node's SHA256 as a differential check, including padding-boundary vectors.
Freeze a separate byte-order golden: SHA256("abc") is
`ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`;
the LE128 integers must be hex `2322ae5dde404141eacf018fbf1678ba` and
`ad1500f261ff10b49c7a1796a36103b0`. Main-circuit digest bits/limbs must match
Node for every complete tuple vector; the golden is not a SHA validity oracle.

This requires **17 compression blocks in one owner circuit**, reused for A/B;
not eight blocks for four outputs. The planned constraint system binds the
full tuple SHA; compilation/checking have not happened.
CF hash consistency, output proof validity, encryption and receipt correctness
remain unimplemented: even a freshly authorized nonsensical CF can satisfy
this authorization-only predicate. No trusted host CF digest oracle remains.

## Mandatory key and encoding constraints

Use `EdDSAPoseidonVerifier` with `enabled <== 1`, wiring PK, R8, S and M;
no validity boolean oracle. Keep its constrained `S < Q`, where
`Q = 2736030358979909402780800718157159386076813972158567259200215660948447373041`.
Additionally require PK/R8 on the Baby-Jubjub curve and prime-order subgroup;
exclude identity PK/R8 for this bounded fixture. Require canonical 32-byte LE coordinate/scalar
encodings: byte ranges and strict field decomposition must be connected
inside the relation, so an out-of-field byte encoding cannot alias a field
element. A host-only decimal parser is insufficient for this encoding claim.
For each coordinate/CM32, connect all 256 byte bits: low 254 to
`Num2Bits_strict`, bits 254/255 constrained zero. For S, connect its low
253 bits to the verifier's scalar and constrain bits 253..255 zero plus S<Q.
No ignored top bits, packed-point decompression or unchecked field reduction.

Enforce `[Q]PK = identity` and `[Q]R8 = identity`, following the actual
[Circomlibjs subgroup test](https://github.com/iden3/circomlibjs/blob/4f094c5be05c1f0210924a3ab204d8fd8da69f49/src/babyjub.js).
Proposed wrapper: constant-Q double/add using pinned
[`BabyCheck`, `BabyAdd`, `BabyDbl`](https://github.com/iden3/circomlib/blob/cff5ab6288b55ef23602221694a6a38a0239dcc0/circuits/babyjub.circom),
with denominator nonzero constraints and exceptional-point review before code.
Do **not** use `EscalarMulAny` as its own subgroup check: its source explicitly
assumes subgroup/nonzero input. The new wrapper is unimplemented/unreviewed;
if valid-point exceptional behavior cannot be handled, stop. No silent
downgrade to `[8]PK != identity` or key searching to hide failures. Membership
must bind the very same PK and nullifying key used for signature/NF checks.

## Frozen schedule and decisive controls

1. Owner processes create independent test signing keys locally and separate
   public nullifying/note material. Each obtains a fresh 32-byte secret from
   Node `crypto.randomBytes`, uses pinned `prv2pub`/`signPoseidon`, and signs
   its baseline record and one explicitly authorized changed-payment record
   (payment NPK increased by 10000 and CF byte 0 XOR 1, values unchanged).
   Only public keys, signatures and other
   required proving material enter the prover bundle; no signing key is
   returned, persisted there or logged. Stop both owner processes before the
   plain prover checks either record. Freeze source/tools, the key-generation
   recipe and every nonsecret input byte before the authorized owner phase;
   pin its public handoff before the witness-check phase. Random signing keys
   are never prepublished test seeds. No claim of host memory erasure
   or signature unforgeability follows from this process boundary test.
2. Check both unchanged intents against the actual compiled R1CS after owners
   stop. They must satisfy it. Record witness-generation rejection separately
   from R1CS-check rejection; do not claim a checked constraint when only a
   parser/generator rejected. Old signatures must reject changed payment
   NPK/value/CM, NF, fee, context, exact anchor or nonce. The separately signed
   changed record must satisfy it. That is new exact consent, not permission
   for an arbitrary later change. A missing/zero/wrong-owner signature rejects.
3. Test replacement PK plus a newly valid replacement-key signature against
   the original input leaf; it must reject at note identity/membership. Change
   the nullifying key with otherwise consistently recomputed NF/signature but
   the original input leaf; it must reject. Test identity, off-curve,
   small-order/mixed-order PK/R8, `S=Q`, noncanonical coordinates and byte
   aliases. Attribute overlapping failures honestly: rejection alone does not
   prove an isolated subgroup/encoding check. Unexpected acceptance stops it.
4. Mutate a CF byte with the old signature; actual R1CS constraints must reject
   even with host validation bypassed. Attempt stale digest limbs and byte=256;
   both reject in the relation. Mutate each other tuple component/output order;
   old signatures reject. A freshly signed arbitrary CF can pass, demonstrating
   the explicit **AUTHORIZATION-ONLY, OUTPUT-VALIDITY-UNBUILT** limit. Wrong
   leaf/root, signed interval and conservation controls reject. Keep every
   failure without retuning; exact negative vectors are frozen before running.

The plain prover intentionally sees each NF, complete output pair, values,
note/NF material, signature and owner/session handle. Label it **NON-PRIVATE**.
No MPC, network anonymity, hidden partition, collaborative proof or malicious
security is tested. Do not label this or any later semi-honest run native
privacy PASS. Frozen active retry/output intersection failures remain.

## Comparison and open RFC decisions

The source-backed alternative is [gnark BN254-in-BN254 owner-proof verification](https://github.com/Consensys/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/std/recursion/groth16/nonnative_doc_test.go#L76-L157):
keep note/NF secrets owner-local, privately verify proof/statement under a fixed
selected VK, with explicit point/subgroup/encoding checks. It avoids exposing
those owner witnesses when shares reconstruct, but adds non-native pairing
work and another proving/codec closure. No cost comparison is measured here.
The smaller signature gate tests real authority separation first; it selects
neither architecture.

Both still require malicious input independence/consistency, full outer-witness
validity before releasing proof-related outputs, authenticated identical-share
handoff and reviewed reactive composition. Valid signatures/inner proofs do
not provide these. TACEO's inspected API remains semi-honest; the full 2025/1026
paper remains unreviewed after PDF403, as documented in source memo 01.

Prospective RFC questions, **before any protocol implementation**: exact
canonical signing/CF relation; strict key identity and owner-local KDF;
every Spend/Exit authorization route; new note/profile/domain/receipt/setup
and recovery compatibility; current native effects/fee binding; accepted-state
and reorg/replay rules; durable consent changes and cancellation; private prover
and exposure threshold; data availability and original-seed direct exits.
Independent exits may still invalidate an exposed batch. No fairness,
reservation, global history or guaranteed asynchronous settlement is supplied.

## Resource and review boundary

Implementation would be one small circuit wrapper, tiny public vectors and
one local driver with owner/prover modes, plus pinned dependency metadata.
No daemon, database, wallet worker, GPU, service, funding or network submission.
Compile once with `--r1cs --wasm --O1`, no `.sym`/JSON R1CS export or setup.
Plan budget: at most 128 MiB additional tool/source closure, 512 MiB scratch,
2 GiB peak RAM and ten CPU minutes for the finite compile/check run; **these
are unmeasured working estimates**, not runtime guarantees. Compiler binary
size is known; npm transitive sizes, constraint/witness sizes and timings are
not. The binary plus three top-level unpacked packages total 34,090,979 bytes,
excluding transitive packages and compressed download copies. Keep only
positive witness artifacts plus negative results, not a large
witness per failed case; no test-source/script execution during setup. Recheck
available disk with Root before any allocation; never crowd out live payouts.
Use one sequential job, no parallel test workers. Inspect/freeze checker curve
worker configuration before execution; package install scripts stay disabled.
If a compiler build, larger closure/resources or setup is needed, stop and
report it. Do not broaden the experiment to spend that budget.

Root approval of this plan would permit only the subsequently specified work.
Before execution, freeze exact source/inputs/tool closure, checks and expected
limits; obtain the required source review. No execution is authorized
here. A future Groth16 setup/new PK needs separate review, is local-test-only
and is **not automatically exempt from the nine-Original audit**. The three
existing selected PK exemptions remain unchanged.
