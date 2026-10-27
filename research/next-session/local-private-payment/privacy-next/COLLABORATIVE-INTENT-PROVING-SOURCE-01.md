# Private intent proving: concrete source gap

**2026-10-26 — source research only; no construction selected or executed.**

**Finding:** an owner-local signature with separately shared proving/nullifier
material is an established alternative to recursively verifying owner SNARKs.
RAILGUN provides a particularly direct circuit example. It can keep spend
authority local even if all proving shares are reconstructed, provided every
consumption route enforces that signature and its exact consent. It would
change the current KPI authorization/profile; sharing today's `owner_secret`
would instead give the servers current spending authority.

Private verification of owner Groth16 proofs is also expressible using existing
BN254 recursion code. **Neither approach supplies a reviewed malicious private
prover pipeline here.** Checking owner proofs/signatures does not by itself
validate the complete outer extended witness, bind a cross-protocol handoff,
or protect intermediate proof openings. Actual batching, private proving,
profile/setup, native acceptance and fee behavior remain unbuilt or untested.

This extends [the design memo](ASYNC-HIDDEN-PARTITION-DESIGN-01.md), not its
selected protocol or the immutable [finite-model closure](model/FINITE-PUBLIC-CLOSURE-01.json).
No model, financial source, key, frozen policy or candidate manifest changed.
No actual wallet/seed, private state/log/truth, proving job or transaction was
read or operated. Downloaded public sources remain temporary research caches.

## What was actually inspected

The ePrint 2025/1026 PDF again returned **403**. Garg's publication list links
back to it; Goel's page also supplies an author-hosted slide deck. Its parsed
text covers all 43 slides; diagrams were not independently visually audited.
The publisher supplied abstract/metadata and HTML preview rather than full PDF;
an exact-title arXiv API query returned no match. **The full paper was not
reviewed.** Earlier primary indexed excerpts cover §§4.1–4.2/5; those are not
substituted for a full construction/security-proof review.
[Paper metadata](https://eprint.iacr.org/2025/1026),
[publisher](https://link.springer.com/chapter/10.1007/978-3-032-01907-3_13),
[author slides, pinned file](https://github.com/aarushigoel/aarushigoel.github.io/blob/b4d30564ef69daa3797c6b53daaf801a5f04590a/slides/Simons_Collaborative_zkSNARKs.pdf).

The deck explicitly separates joint witness extension from specialized proof
computation and requires validity checking before the latter (PDF p.11). Its
honest-majority discussion uses specific additive/affine-error and self-verifying
computation arguments, not a blanket upgrade of arbitrary software (pp.18–35).
Its reactive discussion reconstructs intermediate messages (pp.38–40).
Paper indexed §4.1.1 pp.18–19 concerns invalid extended witnesses; §4.1.2 p.20
concerns consistency across phases; §4.2 p.21 concerns intermediate releases.
No theorem-to-implementation equivalence is asserted here. Authors: Garg,
Goel, Jain, Roberts, Sekar; CRYPTO 2025, publisher pp.396–428.

Fresh official source heads were checked on 2026-10-26. Inspection below is
of the cited paths, not an audit of entire repositories or deployed services:

| Source | Concrete evidence and limit |
| --- | --- |
| [RAILGUN JoinSplit](https://github.com/Railgun-Privacy/circuits-v2/blob/0aa2d13763a9fcfbb7b7ea9c02e004e71f1394bb/src/library/joinsplit.circom#L15-L97) | Entire template inspected: private signature/public key and separate `nullifyingKey`; signature verification enabled unconditionally; key and nullifier material bound into the input note identity. No spending secret is a circuit input. This is a source pattern, not a deployed-circuit/audit claim or native-KAS port. |
| [Orchard keys](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/keys.rs#L152-L215), [FVK](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/keys.rs#L386-L400), [circuit](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/circuit.rs#L667-L704), [ZIP374 roles](https://github.com/zcash/zips/blob/2bdf39494320e5e04057ac93b1794031ebfb00b5/zips/zip-0374.md#L1129-L1193) | Selected paths inspected: `ask` is distinct from FVK `(ak,nk,rivk)`; the circuit binds randomized verification authority; the Prover needs note/FVK/witness data while the Signer supplies spend authorization. Orchard signatures still authorize its specified transaction; they are not unchanged durable KPI intents. |
| [Circomlib 2.0.5 signature gadget](https://github.com/iden3/circomlib/blob/cff5ab6288b55ef23602221694a6a38a0239dcc0/circuits/eddsaposeidon.circom) | Entire gadget inspected; this is RAILGUN's pinned dependency version. Field-native Baby-Jubjub EdDSA/Poseidon is an established circuit source. It is not Ed25519, RedPallas or BIP340. Its selected wrapper must fix `enabled=1`, key/point validity, encoding, subgroup/cofactor and message semantics. |
| [gnark recursion example](https://github.com/Consensys/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/std/recursion/groth16/nonnative_doc_test.go#L76-L157), [verifier](https://github.com/Consensys/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/std/recursion/groth16/verifier.go#L527-L624) | Full example/selected verifier path inspected: BN254 proof verification inside a BN254 circuit through field emulation; inner proof and its public inputs can be private outer witnesses. The generic example also makes the VK a witness: an application must fix or constrain the selected VK, not merely prove some key accepts. |
| [TACEO co-Groth16](https://github.com/TaceoLabs/co-snarks/blob/436f63fa17f2f10ece38c6650df68da99fbc0307/co-circom/co-groth16/src/groth16.rs#L122-L173) and [security contracts](https://github.com/TaceoLabs/co-snarks/blob/436f63fa17f2f10ece38c6650df68da99fbc0307/co-circom/co-groth16/src/groth16.rs#L340-L424) | Selected proving/reduction/drivers inspected. Public API specifies one semi-honest corruption for REP3, or Shamir `n>=2t+1`. The inspected low-level path checks witness dimensions then maps/proves; no full R1CS satisfaction gate was found in that path. Callers may add checks; this was not a full caller audit. |
| [Ozdemir–Boneh artifact](https://github.com/alex-ozdemir/collaborative-zksnark/blob/8cff2c2c45cbc4d5c126082a3d1521f3e662475b/Readme.md), [prover](https://github.com/alex-ozdemir/collaborative-zksnark/blob/8cff2c2c45cbc4d5c126082a3d1521f3e662475b/mpc-snarks/src/groth/prover.rs#L87-L108) | README and selected prover/SPDZ code inspected. The authors explicitly identify this as an insecure benchmarking implementation; the witness-satisfaction assertion in that prover is commented out. It is not an eligible security implementation. No exploit was run. |
| [MP-SPDZ](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/README.md#L142-L178), [client input](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/ExternalIO/client.py#L89-L129) | Malicious-security arithmetic MPC is available as a building block, including dishonest-majority MASCOT. This does not implement the complete private prover, guarantee fair delivery or chain settlement. External client input exchanges masks with all servers; a one-message durable anonymous mailbox is not already supplied. |

Aztec's inspected [key structure](https://github.com/AztecProtocol/aztec-packages/blob/c1b606f97dcd56668ccd8087a794190c34b4c571/noir-projects/fnd/noir-protocol-circuits/crates/types/src/public_keys.nr#L45-L54)
separates nullifier/view/tagging key roles. That structure alone does not prove
that every application spends only through a separately authenticated account
signature; no blanket “nullifier knowledge never authorizes spending” claim
is imported from it.

## Two established approaches; different exposure boundaries

| Approach | Wallet retains / servers receive shares of | Required new work |
| --- | --- | --- |
| Owner-local restricted-intent NIZK | Wallet retains spend/NF secrets and note openings; servers receive intent statement, proof and partition data. | Private in-circuit proof verification, exact fixed VK/statement binding, partition/state relation and malicious private outer proving. Threshold reconstruction exposes the intent map but need not expose the original private proof witness. |
| Owner-local restricted-intent signature | Wallet retains the independent signing secret; servers receive note openings, input nullifier material, paths/blinds, exact outputs and signature. | A signature-bound note identity and mandatory signature predicate, plus the same partition/state relation and malicious private outer proving. Reconstruction exposes substantially more ownership/value/history information, but must still not authorize a new spend. |

RAILGUN concretely binds `Poseidon(publicKey.x,publicKey.y,nullifyingKey)` into
its input note identity and verifies a signature covering root, bound parameters,
NFs and output commitments. Knowing its nullifying key and note openings is
therefore insufficient to authorize different outputs without a new signature,
under the established hash/signature assumptions and complete predicate.
An adapted KPI intent must additionally bind chain/pool lineage, role/profile,
exact recipient/change **complete ciphertext tuples**, integer fee/conservation,
nonce and explicitly permitted anchor/head evolution. Its final aggregate
proof must bind actual current native effects and single-spend state. Ordinary
whole-transaction signatures cannot silently become reusable intents.

For either route the aggregate relation must keep owner records/signatures or
proofs and their partition private, prove a bijection into public NF/output
sets, and verify each owner's consent separately. Public individual Delta,
pair IDs, signature/statement slots or upload handles must not reconstruct the
partition. Ordinary proof aggregation that gives a final prover the map fails
that boundary. Signature separation removes recursive pairing verification;
it does not hide a plaintext constructor or supply an active co-prover.

## Exact incompatibility with the current profile

[Current Spend/Exit](../../../../poc/local-private-payment/relation/src/circuit.rs#L129-L233)
require `owner_secret=s` satisfying `owner=H(tag,D,s,incoming)` and a separate
`k` satisfying the note's key commitment and positioned HMAC NF. Sharing **s**
plus the remaining witness gives the servers the selected consumption secrets.
It must not be relabelled a viewing/proving key. Keeping s local prevents the
current circuit from being jointly proved from shared note openings alone.

A field-native EdDSA alternative could commit the signature verification key
in a reviewed note descriptor instead of that secret-preimage predicate, as
the mature designs do. This requires a separately derived signing secret held
only by the wallet; never derive it from shared nullifier material or sender-
known note randomness. The existing committed `native_pk` is a secp256k1/native
key field, not an already selected EdDSA spending contract. Authorizing a new
BIP340 route through that field would likewise be a new predicate/profile;
no matching signature-circuit adapter was selected here.

Even if Note168/Receipt216 byte lengths are retained, changes to ownership,
KDF labels, invoice derivation and spend conditions require fresh role/domain,
statement/circuit/parameters, Output/Exit compatibility, guest/native policy
and original-seed recovery review. Independent direct exits must enforce the
new legitimate owner's authority without the service. No old note/key/proof
is migrated or reinterpreted. [Spend200](../../../../poc/local-private-payment/relation/src/statements.rs#L15-L64)
still binds the selected whole actual effects and cannot be repacked unchanged.

There is useful algebraic overlap, not demonstrated compatibility: both the
local relation and current TACEO workspace use Arkworks 0.6, and TACEO has a
[LibSnark reduction](https://github.com/TaceoLabs/co-snarks/blob/436f63fa17f2f10ece38c6650df68da99fbc0307/co-circom/co-groth16/src/groth16/reduction.rs#L239-L295).
Matrix order, key conversion, proof encoding, canonical points and exact
two-128-bit-limb statement hashes still need equivalence checks. The selected
MASCOT [field Q/codec](../../../../poc/sender-private-lifecycle/admission/codec.py#L11-L17)
differs from BN254's scalar field; serialized shares are not transferable by
field reduction. Its [current program](../../../../poc/sender-private-lifecycle/admission/kpx9_admission.mpc)
sorts and checked-opens rows; it does not privately verify signatures/SNARKs or
produce an aggregate financial proof. Nothing here finds a current MASCOT flaw.

The [current R0 verifier](../../../../poc/local-private-payment/verification/common/src/lib.rs#L222-L259)
reconstructs actual effects, checks components under its selected profile and
commits the complete projection into its journal; it has no hidden-intent mode.
Giving grouped private records to its ordinary prover reveals the map. The
wallet's [local post-generation proof check](../../../../poc/local-private-payment/relation/src/keys.rs#L207-L237)
also does not provide a distributed invalid-witness privacy gate: collaborative
openings could already have occurred. This identifies a replacement boundary,
not a finding against that owner-local flow.

## Why inner verification is insufficient

1. **Validate the complete outer assignment.** Valid owner proofs/signatures
   do not imply correct state paths, distinct NFs, permutation/equality wiring,
   conservation, context, public effects or every extended wire. The exact
   assignment used by the final prover must satisfy the entire selected R1CS
   before any potentially revealing proof output. A private `Verify` result
   alone does not establish that.
2. **Bind input and handoff.** Select an actively secure input/commit-and-share
   protocol and authenticate the identical assignment through witness extension
   and proof generation. Owner proofs do not substitute for input independence,
   replay/session binding or authenticated resharing. Merely copying MASCOT
   values into semi-honest shares discards these guarantees. TACEO's documented
   [REP3→Shamir handoff](https://github.com/TaceoLabs/co-snarks/blob/436f63fa17f2f10ece38c6650df68da99fbc0307/co-circom/co-groth16/src/groth16.rs#L357-L366)
   is explicitly deterministic, not fresh resharing; no malicious adapter was
   established in this review.
3. **Review every opening.** TACEO opens proof-related points before returning
   the final proof ([lines298–324](https://github.com/TaceoLabs/co-snarks/blob/436f63fa17f2f10ece38c6650df68da99fbc0307/co-circom/co-groth16/src/groth16.rs#L298-L324)).
   The paper's prescribed validity, randomness and reactive-composition
   conditions must be mapped to those actual messages. A final external
   verifier rejecting an invalid proof does not retract intermediate leakage.
   The paper may justify specialized honest-majority kernels; a semi-honest
   label alone neither proves nor disproves that applicability.
4. **Keep application leakage separate.** Even correct malicious MPC reveals
   its specified validity/abort outputs. Define those outputs and committed
   owner inputs before admitting adaptive checks. Generic malicious MPC for
   the complete gated prover is an established theoretical route with abort;
   no such complete implementation is supplied by the current admission code.

Gnark provides useful concrete checks, not an automatic safe wrapper:
[subgroup checking is optional](https://github.com/Consensys/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/std/recursion/groth16/opts.go#L30-L49),
and [precomputed pairing lines have explicit trust conditions](https://github.com/Consensys/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/std/algebra/emulated/sw_bn254/pairing.go#L92-L102).
Its [EdDSA variant](https://github.com/Consensys/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/std/signature/eddsa/eddsa.go#L37-L50)
documents different subgroup/identity semantics from native verification.
Pin one exact scheme and enforce its intended canonical key identity; do not
interchange EdDSA hash variants or assume library type names bind a financial VK.

## Smallest decisive offline prototype — proposed, not authorized here

Prefer first testing the **signature-authority predicate**, using the actual
RAILGUN/Circomlib source pattern, before paying for recursive BN254 pairings.
After design/source review, freeze two fresh unfunded synthetic owners, one
input/two exact outputs each, canonical integer fees and the precise signed
message/key-commitment relation. Keep each signing key in its owner process;
give the prover the remaining complete synthetic proving material. Require a
real signature verifier (`enabled=1`), not a signature-validity oracle.

The decisive controls are altered recipient/CF/fee/NF/context, a substituted
public key or nullifier key, replay in another pool/role, malformed/small-order
keys, and absence of a fresh signature after a requested change. The unchanged
intent must remain provable after owners stop; a newly authorized payment must
require its owner's key. Retain a plain single-prover control that sees the map
as explicitly **non-private**. This is bounded predicate/codec evidence, not
proof of signature unforgeability or native note/exit compatibility.

Only then attempt a private full-witness round trip. Require a selected
malicious witness-generation/prover composition with explicit full-assignment
checking, authenticated handoff, fresh shared proving randomness and an
opening-by-opening review against the primary construction. If no such source
is selected, **stop**: a TACEO semi-honest run may measure compatibility/cost
but cannot discharge that missing oracle. Do not run downloaded exploit code
or promote malformed-witness rejection into a general security proof.

For comparison, the NIZK route's smallest real gate is the official gnark
BN254 recursion example adapted to **fixed selected VKs**, hidden owner
statements/proofs and actual partition/context equality checks. It must also
use the same reviewed malicious outer prover. It leaves fewer owner secrets
exposed under threshold compromise, at the cost of non-native pairing work;
relative time, memory, setup and native fees remain unmeasured.

Neither prototype closes durable intent/current-state semantics, data retention,
original-seed independent exits, active known-cohort abort/retry leakage,
sticky-history/cross-service enforcement or the frozen 2% fee failure. Those
remain separate research and execution gates. No cryptographic subsystem,
new token, admin withdrawal or architecture decision is implemented by this memo.

Inspection identity: author deck commit `b4d30564ef69daa3797c6b53daaf801a5f04590a`,
PDF SHA256 `53e4d3a82fda21a2780752c8fa01ae07c18c5a482f36d3706610f4070efa8975`;
local Cargo.toml SHA256 `32665070753ad63b5787923360586952af3af50a06f711503d9d2a5db694386f`,
Spend statements `bcd3f5f947904fe6fecc4e747b93e0f85a5c611390d0331651e3a1884004e123`,
common verifier `949452a43d9db837067a818e09f9660bf5f6ff9a3adac82094120e532aca6d5d`,
admission program `0873087b92e66d18f535446f35b5c6ed2438eb629a9d75529bd985f0fda68e54`.
Local reads used unchanged helper09. No external chat, actual private material
or third-party executable was used; the final 25-file model closure is unchanged.
