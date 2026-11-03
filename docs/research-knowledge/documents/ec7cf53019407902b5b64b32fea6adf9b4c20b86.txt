# B-private NativeAuthSpend seam: source contract 01

SOURCE PREPARATION ONLY. No compilation, key/setup, signature/witness generation,
constraint run, proof, MPC, RPC, funds or Original job is released. Main final
packet/canary/readback owns resources. This is a new research predicate, not an
accepted Native profile, wallet change or production architecture.

## Exact primitive and point/scalar admission

FIELD_P (the R1CS/WTNS field) is BN254 Fr:
21888242871839275222246405745257275088548364400416034343698204186575808495617.
SUBGROUP_Q is Babyjub prime subgroup order:
2736030358979909402780800718157159386076813972158567259200215660948447373041.
They are different; WTNS header q denotes FIELD_P, not SUBGROUP_Q.

Use unchanged EdDSAPoseidonVerifier and Poseidon from locked Circomlib2.0.5
(selected archive SHA9f80fa85d9c186589998d15e6dcb8ec59a6ed3fe1ec3cb2f753e493d94dd46b6;
its inspected files match official35e54ea21da3e8762557234298dbb553c175ea8d).
The authorization curve is168700*x^2+y^2=1+168696*x^2*y^2, order8*SUBGROUP_Q,
with the stock BASE8 and stock challenge Poseidon(5)(R8x,R8y,Ax,Ay,M).
It is separately typed from normalized Native CV points. No point conversion,
new signature scheme or secret-key-to-public-key gadget is introduced.

The wrapper fixes enabled=1 and adds exact admission for A and R8:

1. BabyCheck on supplied A and R8 coordinates.
2. Auxiliary points PA and PR must be on that same curve. Three unchanged
   BabyDbl stages compute8*PA and8*PR, with BabyCheck at every input/output.
   Each stage explicitly rejects zero denominators1±168696*(x*y)^2 using
   existing IsZero, on exactly the stage's constrained x/y. The final xout/yout
   are constrained equal to the supplied A/R8. No host validity bit is used.
3. Require Ax!=0 andR8x!=0 via IsZero.out=0. Given order8Q, on-curve image[8]
   is the Q-subgroup; in that odd-order subgroup x=0 is only identity.
4. Retain the stock253-bit S decomposition and S<SUBGROUP_Q constraint.
   Transport admits only canonical FIELD_P integers; S+Q remains a valid field
   integer but MUST fail the signature scalar bound in actual R1CS.

Image[8]=E[Q] uses the standard documented order8Q. Conversely a Q-subgroup point
has preimage[INV8]point, INV8=(7*Q+1)/8 since Q=1 mod8. PA/PR are ordinary public
point functions, not the owner's scalar or signing nonce. Denominator guards
make every admitted doubling unambiguous; they may fail closed. Standard
parameter/group-order and mature-verifier arithmetic assumptions remain visible;
this is not a fresh point-count, completeness proof or cryptographic audit.

The OWNER signer MUST check A/R8 on curve, in subgroup, nonidentity and S<Q
BEFORE exporting any signature/handoff. Stock deterministic signPoseidon can
in principle have exceptional r=0; later proof rejection cannot undo disclosure
from such a signature. Stop before export on any degenerate result. Do not
search, retune the seed/message or change nonce generation to obtain a pass.
This stricter admission is a documented liveness boundary. Signing seed,
expanded scalar/prefix, signing nonce and randomized signing secret never enter
the verifier's full shared witness. CV blinding and nullifier k are different
roles and may be present in that witness.

## Canonical encoding and byte/field constraints

AK64 = unsigned Ax32LE || Ay32LE, with each coordinate strictly<FIELD_P.
This is uncompressed authorization-key encoding; never use Native CV's codec
or the host compressed-y/sign-bit codec interchangeably. The signature handoff
contains canonical R8x32LE,R8y32LE and S32LE; transport field canonicality is
checked before conversion, while S<Q is mandatory in the circuit. No modular
normalization of noncanonical external integers.

Each AK byte is a FIELD_P variable range-constrained to8 bits in both component
interfaces. Circom decodes each coordinate with Bits2Num_strict on254 low bits,
forcing the remaining two high bits zero. Both digest limbs use Num2Bits(128).
A byte256 or limb2^128 is an actual invalid field assignment/range control,
not automatically a parser-refusal control. Malformed lengths/hex and raw field
integers>=FIELD_P are parser refusals and never counted as residual failures.

## Explicit new owner commitment and statement

Research domain D is exactly32 bytes0xa6. These test-only8-byte tags are fixed:

| Meaning | ASCII bytes |
| --- | --- |
| Owner-key commitment | KPBPOW01 |
| Input statement | KPBPSP01 |
| Projection prefix | KPBPFX01 |
| Body | KPBPBD01 |
| State112 | KPBPST01 |
| Effects hash | KPBPEF01 |
| Reference Output statement | KPBPOU01 |
| Public journal | KPBPJR01 |

New Note168.owner = SHA256(KPBPOW01 || D32 || AK64 || Note168.incoming32).
The incoming-key binding is retained. This deliberately replaces legacy
SHA256(OWNER_TAG||D||s32||incoming), with no legacy s witness. All other Note168
bytes, current NOTE_TAG, KEY_TAG, NF_TAG, CM_NODE, exact SHA256/HMAC construction,
position32LE/depth16/high-bit bound, NOTE_FLOOR/MAX and canonical CV/blind
constraints are reused from actual native sourcee13fa9/f93c259/350153 without
weakening. D and the statement tag change explicitly for the new research
profile. No current source or key is reinterpreted or reused.

The new200-byte statement is exactly:
KPBPSP01[8] || D[32] || oldCMroot[32] || NF[32] || CVin[64] || effectsHash[32].
SHA256 of all200 bytes is split into lo=LE(digest[0..16]),hi=LE(digest[16..32]).
Owner message M=stock Circomlib Poseidon(2)(lo,hi). This is original Poseidon
arity2 (width3), NOT the newer Poseidon2 permutation. It is a computational
field-message prehash, not injective256-bit encoding. Never reduce a256-bit
SHA digest directly into FIELD_P. The stock signature challenge stays unchanged.

The statement is input-specific through NF, root and CV and role/domain. It
also binds ALL complete effects below. No extra owned input, output reorder,
recipient/change replacement or fee/head refresh inherits an old signature.

## Complete effects and public-input reconstruction

Retain the actual transfer projection layout193-byte prefix +3884-byte body,
body core3756, one NF/two whole Output520 tuples, with only the listed research
tag/domain substitutions in copied public code6727e00a. All current fixed-width,
reserved-zero, version1/1/2/0, integer, CFhash, alias and state/path checks remain.
Do not add an invented laneId. Cross-context scope is actual D,state,outpoint,
script/policy and role. Current entry points reject these new tags/domain;
that acceptance boundary is not weakened.

EffectsHash = SHA256(KPBPEF01 || complete prefix193 || complete body[0..3756]).
This commits action ID, actual reserve point, both State112 values, reserve
values/fee/zero payout, Delta, NF/CVin, both complete520-byte output tuples,
indexed-NF witness and both CM append paths. Prefix commits reserve point,
sequence, input/output amounts and script bytes, counts and body length.
Only final128-byte spend-proof field body[3756..3884] is excluded, preserving
non-circular authorization. Retained output-proof bytes ARE committed.

The public verifier/owner independently parses that whole projection and
reconstructs effectsHash and the new200-byte statement, then selects the TWO
public digest limbs. It does not accept a caller-selected statement digest,
M or proof-valid Boolean. This is the existing Native public-input reconstruction
boundary, not a claim that the ownership circuit checks every packet/state rule.
The Native component hashes its whole statement inside R1CS; the Sig component
constrains its M to the same two limbs; the joint links bind both to those exact
public inputs. A different private effectsHash cannot match the reconstructed
statement without breaking the hash binding.

This source-only one-input seam does NOT validate current Native output proofs
or publish a new accepted Native policy. In the setup-free public fixture,
retained128-byte proof fields are zero, explicitly opaque committed bytes;
they are never called valid proofs. Reference new-profile Output predicates
may check genuine Note/CM/CV/CFhash assignments without proof generation. CF264
fixture bytes may be synthetic with matching hash; ciphertext correctness,
recipient spendability and backup delivery are NOT qualified. The full batch
codec's remove-or-verify-inner-proof decision remains beyond this seam.

## Frozen matrix/witness/ONE/public-prefix composition

Native component:67 instances including ONE, logical instance order
[ONE,lo,hi,AKbyte0,...,AKbyte63]. Preallocate exactly two digest Fr inputs, then
64 byte Fr inputs. Native UInt8 witnesses link to these byte inputs by exact
bit-weight equality. No owner signing secret is allocated.

Signature component: no public outputs and exactly66 public inputs, logically
[lo,hi,AKbyte0,...,AKbyte63]; S,R8,PA,PR and verifier auxiliaries private. Its
main component is an INTERFACE component, never a separately published proof.
Map the66 exact top-level .sym names using the SECOND CSV column (physical
wire index), requiring a bijection over raw1..66. Reject missing/duplicate/-1
indices or extra/uncovered public wires. Canonicalize public-prefix columns
and witness with this same bijection; keep raw private wires>=67 ordered.
Inverse-check every row/term. Require raw R1CSv1, WTNSv2, FIELD_P equality,
all expected sections and no custom-gate/unsupported section. In particular,
reject either section4 OR5, not just a library flag requiring both.

Let native private count Wn and signature private count Ws. Preserve ALL native
and signature rows, predicate labels and coefficients; no non-R1CS predicate
may be dropped. The joint system has3 instances[ONE,lo,hi]. Its maps are:

- Native0→0; native1..66→3..68; native67+j→69+j.
- Sig0→0; sig1..66→69+Wn ..134+Wn; sig67+j→135+Wn+j.

Append exactly68 rows `(left-right)*ONE=0`:
2 Native lo/hi→outer lo/hi,2 Sig lo/hi→outer lo/hi,64 Native AK bytes→Sig AK bytes.
Joint witnesses=132+Wn+Ws; rows=Cn+Cs+68. No component/key/private-prefix ordering
is guessed. The normalized map/hash is selected after the future build and
before any control run. Public final prefix includes NO key/signature bytes.
Same FFT domain/arity would NOT permit reusing any existing setup/VK.

The evaluator requires exact full vector length and raw ONE==1, then evaluates
ALL A*z*B*z-C*z rows, classifying native/signature/link regions. All-zero or
ONE=2 vectors are assignment refusals, not cryptographic residual rejections.
Do not substitute nPrvInputs for the full auxiliary count; full witness length
is nWires, Ws=nWires-1-nPublicInputs-nPublicOutputs.

## Public synthetic fixture and coherent controls

Freeze deterministic recipes, not mutable searches. Public EdDSA seed A=bytes00..1f,
B=20..3f,C=40..5f; use exact stock circomlibjs0.1.7 signer/field APIs. Keys are
KNOWN PUBLIC TEST KEYS; this cannot demonstrate secrecy or unforgeability.
Use native fixture k=0x71*32,incoming=0x22*32,value=2000000000,rho=0x44*32,
native_pk=0x55*32,position3,blind=7LE; replace owner hash with the new key hash.
Build a genuine supplied synthetic CM/NF history and paths through the retained
public wire helpers, not a false accepted-chain claim. Recipient B output is
300000000 sompi, change A1680000000,fee20000000; blinds11/13,Delta=Q-17.
Old/new reserves9000000000/8980000000. Alternate output0 uses coordinator C,
new incoming/rho/k/native_pk, same value/blind; recompute CM/CFhash/state/whole
effects. No genuine proof or financial backing is claimed.

Mandatory source-frozen control families before a future run:

- P01 base coherent new-profile NativeAuthSpend + valid owner signature: SAT.
- N01 coherent coordinator-output replacement, all Native/state/message
  auxiliaries recomputed, ORIGINAL signature: actual signature residual UNSAT;
  native/link regions pass. Generator/parser refusal does not satisfy this.
- P02 same replacement with deliberate NEW owner consent/signature: SAT.
- N02 both components individually SAT with different valid Sig key B versus
  consumed Native note key A: byte LINK rows reject; no host comparison oracle.
- N03 both components individually SAT at base, changed outer digest limb:
  digest LINK rows reject.
- N04 S→S+Q with matching scalar/multiplier auxiliaries: actual scalar predicate
  residual UNSAT, no modulo normalization. Include S=Q as its own range vector.
- N05 byte256 and limb2^128 direct field assignments: actual range residuals.
- N06 wrong note owner/key commitment, position high bits, wrong HMAC NF or
  membership root: actual native predicate residuals with the boundary named.
- N07 role/D/point/fee/output-order changes retain old consent: reject at the
  actual fixed-role/domain/native/signature boundary. No independent Exit claim.
- N08 off-curve, torsion, identity and bad cofactor-image assignments: actual
  new-admission residual controls where a full witness exists. Direct modified
  assignments count; any generator refusal stays separately UNEXECUTED/refused.
- B01 malformed hex/length, noncanonical FIELD_P, missing matrix/custom gates,
  wrong format/field, wrong ONE/vector shape: named boundary refusals, NOT UNSAT.

Ordinary and C++ sanity0 verifier emissions must have BYTE-IDENTICAL R1CS before
normalization. CPP0 means --sanity_check0, not optimizationO0; use the same
selected optimization for both. Standard generated Makefile; no NDEBUG,
generated-code patch or WASM calculateWitness(false) fallback. Every negative
requires its actual complete joined assignment and full ordinary-matrix residuals.
Preserve first unexpected result, raw prior controls and generator failures.
No seed/fixture/threshold retuning or permissive hints after failure.

No setup/proof/PK/MPC, actual secret/Original, funds/RPC or blocked Exit-delivery
work. Independent Exit/every-consume-path rules, old-note migration, original
backup recovery, active retry/cohort intersection and network/routing leakage,
full2/4 conservation/accepted state and fees remain UNRESOLVED beyond this seam.
