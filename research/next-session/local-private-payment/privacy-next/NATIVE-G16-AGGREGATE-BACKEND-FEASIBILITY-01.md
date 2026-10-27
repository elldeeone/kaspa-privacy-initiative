# Current native Groth16 proofs inside an aggregate: backend feasibility

**2026-10-26 — source-only companion to frozen contract
`274be33e05916f7ef01140adcf08e13d26d14e643bee9fee75e2205565c817a9`.
No backend, setup, circuit, runtime or privacy claim is selected.**

**Recommendation:** use the established gnark BN254-in-BN254 verifier as the
first *setup-free constraint-checking candidate*, but treat exact native byte
binding as an unbuilt adapter. Do not start by porting six pairings into the
existing Circom prototype. The existing RISC Zero guest is a useful alternative
for preserving the exact Rust byte verifier; it does not supply a private
distributed prover. Neither route currently qualifies malicious mapping privacy.

The most important missing check is concrete: **change the public Output proof's
128 bytes while keeping the private pairing coordinates unchanged. The actual
outer constraints must reject.** A successful host decoder or `ValueOfProof`
conversion cannot provide this constraint.

## What the current native contract actually is

The native sources below were read through unchanged helper09. They are the
existing local-payment relation, not the completed Poseidon/signature fixture.

* **Receipt216 is a note descriptor, not a Groth16 proof.** Its encoding is
  magic8, D32, index8LE and Note168. Note168 contains owner32, incoming32,
  value8LE, rho32, key-commitment32 and native-pk32. It carries no CV blind.
  Current owner-secret and nullifier-secret remain in the owner's local prover;
  recursive verification receives resulting statements/proofs, not these
  consuming secrets. See `recipient.py:162–183` and `circuit.rs:129–171`.
* **The inner proof is Arkworks 0.6 BN254 Groth16, exactly 128 compressed
  bytes.** It has A in G1, B in G2 and C in G1. The current accelerated verifier
  checked-decodes, reserializes byte-for-byte, rejects trailing data and rejects
  all three identity points before the standard pairing equation. Its G2 bridge
  uses Fq2 c0 then c1 for both coordinates; its padded big-endian conversion into
  substrate-bn is a coordinate conversion, not the compressed-proof wire codec.
  See `g16.rs:9–39,66–95`.
* **The selected role VKs are fixed compressed 328-byte keys with IC length3.**
  `common/src/lib.rs:83–105` checks the SHA, checked decoding, exact reencoding,
  arity and nonidentity key points. Spend and Output key hashes differ. A new
  backend must bind these exact mathematical keys as constants, not accept an
  arbitrary witness key that happens to verify a proof.
* **There are two public scalars per inner proof.** SHA256 of the exact
  Spend200 or Output168 statement is split into first16 and last16 bytes; each
  half is interpreted little-endian. Each scalar is below 2^128. It is not one
  256-bit digest reduced modulo BN254 Fr. An outer circuit must reconstruct the
  exact tagged statement, SHA and ranged halves, then bind the recursive public
  witness to them. See `statements.rs:7–12,33–64,82–111` and
  `common/src/lib.rs:164–170`.

Spend200 is tag8 | D32 | CM-anchor32 | NF32 | CVin64 | effects32. Output168 is
tag8 | D32 | CM32 | CVout64 | CFhash32. Neither statement's field names permit
substitution of the completed prototype's Poseidon CM/NF.

The standard Arkworks decoder is a material part of the existing predicate:
`CanonicalDeserialize::deserialize_compressed` calls compressed mode with
`Validate::Yes`; affine point validation checks on-curve and subgroup membership.
These facts were checked in the installed 0.6.0 sources, not inferred from the
word “compressed.” [Serialization API](https://docs.rs/ark-serialize/0.6.0/ark_serialize/trait.CanonicalDeserialize.html),
[affine validation at the crate's recorded source commit](https://github.com/arkworks-rs/algebra/blob/bffa52711f225e888c1a91e1ec9fc59f2d9d5c94/ec/src/models/short_weierstrass/affine.rs#L414-L430).

## Exact public-byte binding is required

`common/src/wire.rs:119–128` takes each whole Output520 tuple as:

`CM32 | CV64 | CF264 | CFhash32 | compressed-Groth16-proof128`.

The proof is `row[392..520]`. These complete tuples, including Output proof bytes,
are inside the body core authorized by the current Spend effects digest. The
frozen 2/4 contract preserves that complete-effects boundary.

Consequently, parsing public proof bytes into host coordinates and passing those
coordinates as an outer private witness is insufficient. A malicious assignment
could otherwise supply one public byte string and unrelated valid pairing
coordinates. Hashing the public bytes into effects does not establish their
equality to the proof used by the pairing gadget.

The selected adapter must constrain canonical Arkworks byte/point equivalence,
including field range, flags/sign convention, point identity, G2 coefficient
order and subgroup semantics. Merely checking an uncompressed coordinate
representation on the host is a narrower *assignment compatibility* test. This
source pass did not find or qualify an official gnark gadget that directly
decodes this exact Arkworks compressed proof format. The mathematical verifier
is available; the exact-byte adapter is still unbuilt. Private Spend proofs also
need the contract's stated canonical/nonidentity semantics, even though their
proof bytes are not a public output tuple.

## Candidate backends

| Candidate | Source-backed compatibility | Remaining boundary |
| --- | --- | --- |
| **gnark emulated BN254 recursive Groth16** | The exact official `0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46` example verifies BN254 Groth16 inside a BN254 outer circuit. Existing Ark proof points and fixed VK can be adapted mathematically; no new inner setup or re-proving under gnark is implied. | Exact compressed-byte binding above; constant selected VK; in-circuit statement SHA/two128-bit inputs; subgroup/nonidentity and complete arithmetic; full state/value/partition relation. The existing Circom aggregate is not a gnark circuit. |
| **Existing RISC Zero / Rust verifier route** | Current guest already calls the current Rust predicate, whose G16 verifier performs checked canonical byte decoding. A separate research guest can reuse that exact byte-verification semantics rather than introduce nonnative point-decompression constraints. | A new 2/4 research relation/image/journal still needs its own source review. The old 1/2 image/profile cannot accept 2/4. An ordinary prover sees private inputs and their mapping; zero knowledge toward the receipt verifier does not hide them from that prover. No distributed prover is supplied. |
| **Current Circom prototype plus circom-pairing example** | The inspected original author's `circom-pairing` source is a BLS12-381 pairing/BLS-signature demonstration. | It is the wrong inner curve for these BN254 proofs, explicitly a demonstration, and is not a turnkey current-native verifier. No compatible maintained Circom BN254 exact-byte verifier was established by this bounded pass. This is not a claim that none exists anywhere. |
| **TACEO coSNARK backend** | Its current `436f63fa17f2f10ece38c6650df68da99fbc0307` co-Groth16 API accepts Arkworks pairing types, matrices and shared extended witnesses; it includes a LibSnark reduction. | This is a prover backend, not a recursive-verifier gadget. No gnark-to-that-matrix/key/witness bridge was qualified. Its REP3 and Shamir APIs explicitly assume semi-honest corruption. They do not qualify the contract's malicious complete-witness pipeline. |

Gnark's exact APIs and their trust conditions are documented in the companion
[gnark source assessment](GNARK-NATIVE-G16-AGGREGATE-SOURCE-01.md). Its
[BN254 example](https://github.com/Consensys/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/std/recursion/groth16/nonnative_doc_test.go#L76-L157)
is a compatibility candidate, not a fixed financial-key wrapper. The selected
[subgroup option](https://github.com/Consensys/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/std/recursion/groth16/opts.go)
and [precomputed-line trust contract](https://github.com/Consensys/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/std/algebra/emulated/sw_bn254/pairing.go#L92-L102)
must be used correctly. In particular, untrusted dynamic proof B must not carry
caller-supplied, unbound precomputed pairing lines.

RISC Zero is pinned locally at `risc0-zkvm=3.0.3` with dev mode disabled. Its
upstream v3.0.3 commit is `14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6`.
The [guest API](https://github.com/risc0/risc0/blob/14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6/risc0/zkvm/src/guest/env/mod.rs#L212-L263)
reads private guest inputs, while the journal is public. Its
[composition API](https://github.com/risc0/risc0/blob/14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6/risc0/zkvm/src/guest/env/verify.rs#L22-L61)
composes RISC Zero receipts; it does not directly recognize arbitrary Arkworks
Groth16 proofs. Those still require executing the actual G16 verifier. Its
[STARK layer](https://github.com/risc0/risc0/blob/14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6/website/docs/reference-docs/about-starks.md)
is transparent, while [Groth16 wrapping](https://github.com/risc0/risc0/blob/14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6/website/docs/proof-system/proof-system.md#L15-L27)
is a separate proof layer. A succinct-STARK reference experiment need not create
new circuit-specific Groth16 parameters; it would still require a new guest and
actual proving if later authorized.

The original [Circom pairing source](https://github.com/yi-sun/circom-pairing/blob/107c316223a08ac577522c54edd81f0fc4c03130/README.md#L14-L36)
explicitly specifies BLS12-381 and demonstration scope. Its published hardware
and circuit costs are for those different circuits, so they are not estimates
for this six-proof BN254 aggregate.

TACEO's [README](https://github.com/TaceoLabs/co-snarks/blob/436f63fa17f2f10ece38c6650df68da99fbc0307/README.md#L8-L39)
describes Circom/Noir tooling, not an automatic gnark frontend. Its inspected
[prover core](https://github.com/TaceoLabs/co-snarks/blob/436f63fa17f2f10ece38c6650df68da99fbc0307/co-circom/co-groth16/src/groth16.rs#L113-L161)
checks witness dimensions before its reduction/proof path; that is not a full
R1CS satisfaction check. The [public API security contracts](https://github.com/TaceoLabs/co-snarks/blob/436f63fa17f2f10ece38c6650df68da99fbc0307/co-circom/co-groth16/src/groth16.rs#L318-L400)
state semi-honest thresholds and deterministic handoff behavior. The
[LibSnark reduction](https://github.com/TaceoLabs/co-snarks/blob/436f63fa17f2f10ece38c6650df68da99fbc0307/co-circom/co-groth16/src/groth16/reduction.rs#L217-L324)
is useful algebraic overlap, not evidence that every matrix ordering, key and
share encoding is interchangeable. A complete malicious prover still needs
full extended-assignment checking before openings, authenticated identical
handoff, suitable fresh proving randomness and an opening-by-opening argument.

## Smallest decisive synthetic next fixture — specification only

1. **Freeze exact assets and authority.** Use only fresh, unfunded, explicitly
   public synthetic Note168/Receipt216 owners. Select the already existing public
   Spend and Output PK/VK/manifest identities. First use one genuine proof per
   role, with exact statement bytes and canonical proof128, as the smallest
   adapter fixture. The public VKs are embedded and pinned in the current
   component profile. No proving-key file was opened or new proof generated in
   this task; a missing eligible PK or public fixture is a blocker, not permission
   to regenerate a setup. Never use campaign Original material to fill this gap.
2. **Check the candidate outer constraints, without outer setup.** Compile one
   fixed-key per-role verifier wrapper and check its complete assignment with
   the backend's actual constraint solver. Include the statement SHA256, exact
   two ranged little-endian128-bit inputs and exact compressed proof-byte binding.
   A host verification bit is not an input. Constraint checking requires no new
   outer Groth16 PK/VK; it is not an aggregate proof and establishes no privacy.
   Keep unchanged standard Arkworks and current accelerated verification as
   differential references. An unimplemented byte adapter means this step is
   UNEXECUTED, not “passed through ValueOfProof.”
3. **Freeze decisive negative assignments.** Change public Output proof128 bytes
   independently of pairing coordinates; change coordinates independently of
   bytes; change a statement byte or limb; reverse digest halves or byte order;
   substitute the other role VK; alter compressed flags or introduce trailing
   bytes; use identity/noncanonical/out-of-subgroup proof material. Where malformed
   bytes fail decoding, record parser rejection separately. Where a validly
   structured but inconsistent assignment is possible, require actual outer
   constraint rejection, not a witness-generator assertion. Include supported
   zero-scalar/complete-arithmetic controls without pretending a fabricated
   SHA preimage is a genuine current statement.
4. **Only after adapter equivalence, consider the frozen six-proof relation.**
   Reuse the two Spend/four Output counts and all exact-effects, permutation,
   state, CV, distinctness, antiwrap and supplied-head controls in contract274be.
   Owners authorize the exact same 2/4 effects before stopping. Reusing already
   authorized 1/2 proofs is invalid. The unchanged current 1/2 parser/profile must
   continue to reject the research frame. A later final proof may require new
   outer parameters or a transparent proof choice; this source task authorizes
   neither. The complete malicious distributed prover remains a separate gate.

There is **no source-backed target constraint count, peak memory, proving time,
GPU benefit or six-proof fee result** here. Existing library examples and
different-curve benchmark tables do not establish those measurements. First
measure the selected complete adapter and negative-constraint method if a later
implementation proposal is approved; do not size a large proving deployment
from API availability.

## Local source identities and limits

All paths below are repository-relative. SHA256 identifies the exact inspected
public sources; the native files were not edited.

| Source | SHA256 |
| --- | --- |
| `poc/local-private-payment/relation/Cargo.toml` | `32665070753ad63b5787923360586952af3af50a06f711503d9d2a5db694386f` |
| `relation/src/statements.rs` | `bcd3f5f947904fe6fecc4e747b93e0f85a5c611390d0331651e3a1884004e123` |
| `relation/src/circuit.rs` | `e13fa9bd6ba33bd01b71e824d10944b3d8561854b3c026f997b282cf57fde4b0` |
| `relation/src/keys.rs` | `84095f2c53342f869e8bc833b6af44694e847bd55484454d103e01e93177b955` |
| `verification/common/src/g16.rs` | `c6ce48be94c702858b6a9a7093ae835cf4d2afd7808e56eb2a9a762c1d21b36a` |
| `verification/common/src/lib.rs` | `949452a43d9db837067a818e09f9660bf5f6ff9a3adac82094120e532aca6d5d` |
| `verification/common/src/wire.rs` | `136f7b1115a64d08e9789114be04d0fa3de90b05da5aa2216bd686effc7b6562` |
| `verification/component-profile.json` | `9fd9651dfd96faa864705e67b9bbcf7b76503963c99d14605243859699b24018` |
| `verification/guest/src/main.rs` | `e762fbb2b9792a8b257dc77f2f08c75abe8e7cb045987bbc92cc57fd6a93f4ed` |
| `verification/guest/Cargo.toml` | `1854dabb8685639eb814dfb0f77d09bc250f77084e5f634915277e631605c76d` |
| `poc/future-recipient/v2/recipient.py` | `93a3d01b99e6c8f0ac6f3d682d41f65d2cc2d40489d1fbd4226f1fb351edd1d2` |

Rows after the first relation row are below `poc/local-private-payment/`, except
the explicitly rooted recipient row. Existing Spend VK SHA is
`b02bbf6a31a57c6132ae1ecaa680e1e955946fc1076fbe4f7e58142407b57203`,
manifest `4d28ba947357debb486e623c82ef03e778d3b986be9891696eca022926a08464`;
Output VK is `2839d491047edd5664db65af3fa92a7194d959e7f94f723eac982aa918c785e6`,
manifest `c400914d0b68c8f7846c198fd462210b35212f3e893f1f7801c457ad0069d729`.

Installed Arkworks public-source checks: ark-serialize0.6.0 `src/lib.rs`
SHA `e253b17896521de7958df388a0151c0824b24028a06ca46cfeb995f98d2a1d02`;
ark-ec0.6.0 affine source SHA
`d433d2e802ce603423341671d186fa1b5f9e637f07336eeae1cefc8ae24cf96e`,
with recorded upstream commit `bffa52711f225e888c1a91e1ec9fc59f2d9d5c94`.
The exact compressed-bit decoder and its future outer implementation have not
been equivalence-tested here.

No private owner material, ActualOriginal, STATE/PLAN, controller log, model
tuple or private key was read. No cryptographic implementation, compile, proof, setup,
benchmark, install, funding or network trial ran. Only official primary sources
were used for external software claims. The frozen plan, active 597/21 sources,
profiles, five coordinated documents and publication candidate were not edited.
This note does not retire current Output encryption/delivery gaps, malicious
MPC, current-native 2/4 acceptance, independent recovery or the fee target.
