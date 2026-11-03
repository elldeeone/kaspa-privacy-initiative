# Owner-private prototype: shared financial and construction contract

2026-10-24 UTC. Proposed with [ADR0063](../../../docs/adr/0063-owner-private-payments-prototype.md)
for root's second-pass acceptance. New unfunded research domain only. Existing
funded/closed evidence is unchanged; this contract does not import real wallets.

## Domain, amounts and existing note semantics

All implementations use public D = SHA256 of exact UTF-8/ASCII bytes
`KPX7 owner-private payments prototype v1 / UNFUNDED ONLY`, no newline:
`32b4f31a58cc52d22862c20a923c59cdd0127785e9998f632eae2b3bb319919d`.
Keys and fixtures are fresh synthetic owner-local material. D is distinct from
all funded profiles. It is independent of future setup/VK/image identifiers.

The first fixed shape is three real input notes, one per owner, and six positive
outputs, two per owner. The output grouping is private. Native P0 has one
reserve input/one continuing output, payout zero, `reserve_after=reserve-fee`.
Amounts are integer sompi; every real note value is in
`[60_000_000, 2_870_000_000_000_000_000]`. Native reserves and fees receive their
existing explicit policy bounds. No modular field element is an amount decoder.
Even `6*MAX < 2^64`, far below either selected field; all sums use checked wide
integer/range semantics. No padded/dummy note is selected in this shape.

Reuse the existing Note168 fields in this exact order:
`owner32|incoming32|value_u64LE8|rho32|key_commitment32|native_xonly_pk32`.
The last key stays in the private note/encrypted delivery, never the new public
Spend statement. Reuse domain-separated SHA note/owner/key commitments and
HMAC original positioned NF from the existing prover:

```
owner = SHA256("KPX1OWN\0" || D || owner_secret32 || incoming32)
key_commitment = SHA256("KPX1KEY\0" || D || nullifier_secret32)
CM = SHA256("KPX1NOT\0" || D || Note168)
NF = HMAC-SHA256(nullifier_secret32,
                 "KPX1NF\0\0" || D || CM || position_u32LE)
```

Position is constrained to16 bits and membership in the accepted CM root.
Spend200 does not expose the note count. The count bound follows from the
accepted-tree invariant: occupied real leaves form the prefix below n and the
remaining leaves are the distinct empty value. The initial fixture/admission
and native sequential append checks must establish/preserve that invariant;
do not claim an unavailable direct position<n circuit check.
NF is nonzero, unique/currently unspent, and independent of attempt, effects,
MPC roster, output choice and retry. The native verifier authenticates current
NF updates separately from private membership. Preserve the accepted note's
opening, authority and original NF across retries.

Reuse owner-local Invoice208, Receipt216 and CF264 sealed delivery in the new
domain. Recipients decrypt, reconstruct their invoice/note and CM, and verify
the associated genuine Output proof before accepting a payment. Its creator
checks the CV opening. Fresh input CV randomness is generated at spend time;
the recipient does not need to recover a previous output CV blinding.

## Curve, public parameters and strict encodings

Use a coherent published Arkworks **0.6.0** closure. Normalized BabyJubjub
`EdwardsProjective` has equation `x²+y²=1+d*x²*y²`, cofactor8 and
`d=9706598848417545097372247223557719406784115219466060233080913168975159366771`.

```
coordinate/R1CS field p = BN254 Fr
21888242871839275222246405745257275088548364400416034343698204186575808495617
blinding/MPC scalar field q = BabyJubjub Fr
2736030358979909402780800718157159386076813972158567259200215660948447373041
```

Use stock `ark_crypto_primitives::commitment::pedersen::Commitment` over this
curve with `NUM_WINDOWS=1, WINDOW_SIZE=64`. Call its standard setup once with
`rand_chacha=0.3.1` `ChaCha20Rng::from_seed(seed)`, where seed is SHA256 of exact
ASCII, no newline:
`KPI owner-private payments v1 / transparent Pedersen parameters / BN254 BabyJubjub`.
Seed hex is `bc05b21a635868b772c207e266b1bb5443ee2ddd5de3b108b0227c14fc795c87`.
Setup draws the randomness power table first (base R), then the one message
power table (base V). The existing sampler chooses y/sign, recovers x, clears
cofactor8: it does not disclose a scalar multiplying another generator.
Publish exact V/R, every power-table/parameter hash and package/source pins.
Fail closed for identity, V=R, V=-R or invalid points; never replace them with
chosen points or silently select another seed. This transparent-parameter
argument assumes the pinned sampler/RNG and discrete-log hardness; it is not
a proof that nobody knows a relation. No `test_rng`/unspecified `StdRng`.

`CV(v,r)=v*V+r*R` for eight little-endian sompi bytes and canonical r in `[0,q)`.
Canonical point wire is `x32LE|y32LE`, coordinates strictly below p. Native
decoders require exact64 bytes/no trailing data, on-curve/prime-order checks,
round-trip equality and nonidentity for individual CVs. Identity aggregate
differences are allowed. Scalar wire is exact32LE below q, including zero.
Decimal `FromStr`/mod-order reduction is not a strict wire decoder.

The circuit derives CV from fixed subgroup generators and canonical r, then
constrains its full canonical coordinate bytes equal to the statement. All256
scalar bits must be below q: stock randomness-gadget truncation or a comparison
against the larger R1CS field p is insufficient. No public beta_i or beta_i*R.

## Independent genuine proof statements

All tags below are eight literal ASCII bytes. There is no owner/subset identifier
in Output, no public spend native key and no per-action output digest.

```
Spend200 = "KPX7SP01" | D32 | oldCMroot32 | NF32 | CVin64 | EffectsDigest32
Output168 = "KPX7OU01" | D32 | CM32 | CVout64 | CFH32
CFH = SHA256(CF264)
```

For each statement compute SHA256 **inside the circuit**, constrain all fields,
and expose exactly two BN254 Fr inputs from digest bytes0..16 and16..32 as
unsigned128LE integers. No full256-bit digest reduction, unused public digest,
caller-selected VK or host proof-valid flag is accepted. Use fixed Spend and
Output VKs, genuine compressed128-byte BN254 proofs and validated328-byte VKs.
Create new separate Spend/Output Groth16 setups with fresh private OS entropy;
the public Pedersen parameter seed is **not** setup entropy. Keep new proving
keys and any toxic-waste material private/task-local, publish only the selected
public VK/provenance, and never import an old funded proving key.

Spend private witness: Note168, owner/nullifier secrets, position/depth16 path,
fresh r_in. Prove exact note/owner/key commitments, bounded positive value,
accepted-root membership, original positioned NF and CV(value,r_in). Bind the
provided EffectsDigest through the statement hash. The owner generates this
proof only after independently checking all final effects and its required
payment/change output tuples. This is the selected financial authorization.

Output private witness: Note168 and fresh r_out. Prove exact note CM, bounded
positive value, CV(value,r_out) and the full statement hash including CFH.
CFH binds the delivered bytes; **NaCl encryption correctness is not proved**.
Recipient-side validation above supplies detectable delivery rejection under
I-14, not an invented encryption-proof claim. Output proofs are made before
mixing and contain no final EffectsDigest or owner-output subset hash.

## One private tuple/sum attempt

The public descriptor fixes D, fresh session32, exact ordered three-party roster
and ephemeral identities, common prior context/effect policy, tuple schema and
counts, both VK/parameter/image identities, generator identities, selected
engine/program/field and bytecode/schedule hashes. Every owner checks it before
input; session is bound into compiled program/report identity. No private tuple,
tuple hash, blinding contribution or plaintext input-directory content reaches
the coordinator. Public spend NF/CVin skeletons may retain input-owner labels;
the target is hiding unrelated owner-to-output mapping.

```
OutputTuple520 = CM32 | CVout64 | CF264 | CFH32 | OutputProof128
beta_i = fresh_r_in_i - r_out_i0 - r_out_i1  (mod q)
```

Each owner supplies only its own two tuples and beta to its isolated MASCOT
party. Pack a complete tuple into17 little-endian31-byte limbs; final7 padding
bytes are zero and every limb is below2^248<q. No modulo reduction/truncation.
The stock six-row `secure_shuffle()` moves complete17-limb rows, with secret
internal padding to eight handled by the library. It checks malicious switch
bits and composes all three participants' private permutations. Use fresh live
preprocessing and checked reveals, never fake/unchecked/INSECURE execution.

The same stock program reveals six complete shuffled rows and only
`Delta=sum(beta_i) mod q`. Require all parties succeed and agree byte-for-byte
on session/rows/Delta; no surviving-subset opening/retry. Wrong prime, bad row,
padding or session is rejected. Raw parser/engine diagnostics stay owner-local;
the wrapper exports validated final results or a neutral failure. The full
coordinator transcript and allowed colluder observations remain in scope.
The existing [construction design](../../../poc/owner-private-payments/construction/DESIGN.md)
pins stock APIs, honest-permutation assumptions and operational isolation.

## Financial effects and native acceptance

EffectsDigest is SHA256 of tagged `KPX7EF01` canonical public financial effects:
session/roster; unfunded domain/version; actual native header/previous input
point; current/prior/successor state and roots; reserve values and exact fee;
zero payout in P0; ordered three NF/CVin records; all six **complete** mixed
OutputTuple520 records including Output proofs; Delta; and exact public
NF-insert/CM-append transition data. The exact
[verification wire contract](../../../poc/owner-private-payments/verification/DESIGN.md)
selects Body10780/Core10396, native prefix193 and journal104:
`SHA256("KPX7EF01"|nativePrefix193|body[0:10396])`. The last384 body bytes are
the three Spend proofs. Derived EffectsDigest fields,
all three Spend-proof bytes and outer receipt bytes are omitted. No ambiguous
JSON reserialization or caller-supplied digest selects financial meaning.

Every owner recomputes the same canonical digest, verifies all output proofs,
own-output inclusion and public global balance before generating its Spend proof.
The new native guest independently recomputes that digest, verifies all nine
proofs, rejects duplicate/missing components and original NFs, authenticates
current state and exact native projection, and checks directly:

`sum(CVin)-sum(CVout)-fee*V = Delta*R`.

No Binding signature is needed: public Delta would let anybody form one.
No separate authorization key/signature is exposed. Valid Spend-proof witness
malleability is explicitly allowed because Spend proofs are excluded from
EffectsDigest; changing proof bytes while preserving the same valid statement
does not change authorized financial meaning. The native receipt journal still
binds the actual complete body/proof bytes, new image/VKs/domain, exact native
projection and transition. New covenant code verifies that receipt against its
real context; synthetic supplied context is never called accepted-chain state.
The native transaction projection has no network/genesis-ID field. D selects
this unfunded domain and the host selects its native077/TN10 test context;
neither is an independent consensus attestation of the current network.

After failure use fresh attempt/MPC ephemeral material, input CV blindings and
complete output material. Preserve accepted input openings, authority, backup,
financial setup and stable original NF. No post-authorization error/blame path
discloses an honest owner's tuple map. Old authorized valid bodies can still
settle; reconcile accepted state/NFs before retry or exit. Unknown is INCOMPLETE.
Dependency loss safely halts; no admin rescue or invalid state is accepted.

## Source basis

The [current library source note](CURVE-GENERATOR-SOURCES-01.md) records published
0.6 crate checksums, actual VCS identities (including dirty-source metadata),
point sampler, native-field gadget, canonical decoding and stock Pedersen setup.
Its retained0.5 comparison and iden3 alternative are not selected dependencies.
The independent commitment-source review checks the same exact package/source
boundary and scalar-gadget pitfall; its retained artifact selector is supplied
separately by its author.

Reuse source-grounded comparisons already inspected in
[native proof composition](../../native-proof-composition-source-review-2026-10-22.md)
and [construction](../private-construction/CONSTRUCTION.md): Kaspa KIP16/current
BN254 and RISC0 native dispatch, vProgs/research exact-state/journal binding,
Sapling separate spend/output commitments, Orchard authorization versus balance,
Aztec allowed-key/state continuity, RAILGUN bound effects/ranges/current NF,
Monero separate commitment/range/auth responsibilities and MWEB public boundary
accounting. No alternative VM/runtime/token/consensus stack is imported.
Relevant selected official sources were inspected again for this contract;
historical source pins are not claimed to be every project's latest head.

[ValueShuffle](https://fc17.ifca.ai/bitcoin/papers/bitcoin17-final6.pdf), pinned
SHA256 `5b5217e0641211e53434d6372ac516ba9f7e43ea80a527d97ae55a130b3cde6f`,
supplies complete confidential output mixing, private aggregate balance and
checks-before-final-authorization/fresh-retry discipline. This prototype instead
uses MP-SPDZ v0.4.4 commit `113c4e47dd94bca9ecab029d2f0abe649bea5c52` stock
malicious secure shuffle/sum, so its cross-protocol and native composition are
new review obligations, not the paper's proven protocol. No fairness, adaptive
corruption, malicious-host isolation or robust termination is claimed.

Attack the actual integrated body with at least two eligible honest owners;
freeze observer, truth, rules and controls before outcomes. Retain public
endpoints/counts/timing, colluder knowledge, all-but-one negative, previous
amount/ancestry failures and transparent entry/exit limitations. Passing a
bounded functional/attack experiment is not a general privacy/security proof.
