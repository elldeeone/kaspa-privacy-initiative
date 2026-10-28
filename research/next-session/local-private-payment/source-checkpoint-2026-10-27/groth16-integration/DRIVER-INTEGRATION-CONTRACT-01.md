# Concrete MASCOT Groth16 integration contract

2026-10-27. Source plan only; no build, setup, proof, engine, private input,
Original, TLS/log body or financial execution. The current 489-file publication
selection is unchanged. Every implementation described below is **port required**
unless explicitly identified as existing upstream machinery.

**Recommended first implementation:** a small C++ MASCOT prover that ports the
selected co-snarks **LibSnarkReduction and proof formula**, uses stock MP-SPDZ
authenticated scalars/group MAC checks, and uses an explicit-root adapter over
established mcl arithmetic/NTT butterflies. Keep Arkworks as the public
matrix/key exporter and independent final verifier. This avoids extending the
legacy semi-honest Rust driver contract and importing a second network stack.
It still requires real group wrappers, public-model/codec agreement, the
owner-client ingress supplied by the parent, and a full-proof qualification.

## Exact source boundary and what exists

- co-snarks `436f63fa17f2f10ece38c6650df68da99fbc0307`: the full Groth16 formula,
  LibSnark/Circom witness maps and pure FFT/MSM algorithms exist. Its public
  proving entries select REP3/Shamir semi-honest drivers. `prove_inner` is
  private; its current half-share path is **not** a MASCOT integration.
- MP-SPDZ `113c4e47dd94bca9ecab029d2f0abe649bea5c52`: authenticated `Share<Fr>`,
  MASCOT preprocessing, Beaver multiplication, public-constant tagging and
  checked group-opening patterns exist. Existing ECDSA group examples are
  interface patterns, not a BN254/Groth16 implementation. Never reuse their
  diagnostic secret-key openings or switches disabling checks.
- mcl `9f49ba06593e2d426ab6fb9b0e17bc125a6f720c`: established G1/G2 arithmetic
  exists for explicit **BN_SNARK1**. Default `initPairing()`/`BN254` selects a
  different curve. The standard NTT header is also **not a drop-in**: its
  constructor explicitly says its root and 32-bit assumption are for
  BLS12-381. BN254 Fr has two-adicity28.
- The completed scalar gate establishes selected stock-binary exact-Fr
  arithmetic compatibility on public synthetic inputs. It did not execute
  this native C++ low-level interface, authenticated group operations,
  external owner-client inputs, FFT/QAP, random proof masks or Groth16.

Source anchors: [prover core](https://github.com/TaceoLabs/co-snarks/blob/436f63fa17f2f10ece38c6650df68da99fbc0307/co-circom/co-groth16/src/groth16.rs),
[driver trait](https://github.com/TaceoLabs/co-snarks/blob/436f63fa17f2f10ece38c6650df68da99fbc0307/co-circom/co-groth16/src/mpc.rs),
[reductions](https://github.com/TaceoLabs/co-snarks/blob/436f63fa17f2f10ece38c6650df68da99fbc0307/co-circom/co-groth16/src/groth16/reduction.rs),
[stock authenticated share](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/Share.h),
[mcl NTT assumptions](https://github.com/herumi/mcl/blob/9f49ba06593e2d426ab6fb9b0e17bc125a6f720c/include/mcl/ntt.hpp#L94-L153).

## Required private types and owner ingress

Use the same exact Fr as the scalar gate:
`21888242871839275222246405745257275088548364400416034343698204186575808495617`.
The group base field is distinct:
`21888242871839275222246405745257275088696311157297823662689037894645226208583`.

`AuthScalar` is stock `Share<gfp_<0,4>>`: it retains both local value and MAC
components. `AuthG1` and `AuthG2` adapt stock `Share<GroupValue>` to separate
BN_SNARK1 group wrappers whose Scalar field is this same Fr. Internal shares,
query points and the explicit H-padding point may legitimately be identity.
Apply nonidentity requirements only in their actual proof/VK roles. Admission
must check canonical integers, curve equation, subgroup and exact curve
parameters; no implicit Mod import, default-curve selection or unexamined mcl
serialization mode. Final Native128 codec equivalence remains a separate gap.

The same immutable `LinearMacContext` supplies party ID and that party's private
alpha share to public-constant operations. For a public scalar c, value share is
c at the designated constant party and0 elsewhere, while every party's MAC
share gains alpha_i*c. Public points follow the stock analogous group rule.
Adding c/P only at party0 without MAC updates is wrong.

Owner inputs must arrive through the separately pinned **strict external-client
DDNNT triple-mask path**, not `get_input_from(party0)` with a clear witness.
The owner connects to all three authenticated TLS endpoints; receives only
fresh triple VALUE components; requires3n, reconstructs/checks A*B=C, and sends
m=x+A to all. Servers produce `AuthConstant(m)-[A]` while MAC components remain
server-side. No one-mask fallback, no client-provided unauthenticated MACs, no
trusted cleartext witness dealer. Parent-owned source review must bind the
exact client/server API, Fr, job and model before this is an executable choice.
Do not downgrade that requirement to obtain a full-proof demo.

The toy clients below have publicly known numbers but must exercise that actual
external private-input protocol. Fixed toy client slots disclose the toy
ownership map. This gate does not establish hidden routing for real notes;
that later protocol still needs an authenticated variable map and private
permutation/assignment, without owner-labelled public witness offsets.

## Exact operation map

The proposed declarations are in `API-CONTRACT-01.hpp`; they are not a compiled
implementation. All network, preprocessing and check operations run in a single
ordered MASCOT context. Parallel work may contain only pure local arithmetic.

| Existing co-snarks operation | Required authenticated port |
| --- | --- |
| `rand(net,state)` | `random_auth(ctx) -> AuthScalar`: call `ctx.protocols.preprocessing.get_random()`; fresh independent calls for r and s. No `Share::randomize(privatePRNG)`, fixed public masks, reused owner masks or exposed randomness. |
| `evaluate_constraint(id,row,pub,priv)` | `evaluate_linear(row,authenticated_assignment) -> AuthScalar`; pre-promote the public prefix with alpha context, keep every private value/MAC pair, check all indices and full dimensions. |
| `evaluate_constraint_half_share(...)` | Delete the downgrade; C-row evaluation returns the same authenticated scalar type as A/B. |
| `promote_to_trivial_shares(id,pub)` | `promote_public(linear_ctx,pub)`: stock authenticated constants, including literal ONE. Party ID alone is insufficient. |
| `local_mul_vec(a,b,state)` | `multiply_batch(ctx,a,b) -> Result<vector<AuthScalar>>`: stock `init_mul`, `prepare_mul`, `exchange`, `finalize_mul`; ordered network operation, equal lengths, preserve authentication. |
| `distribute_powers_and_mul_by_const` | Pure local multiplication of **both** scalar components by each admitted public coefficient. |
| `to_half_share` | Remove. No raw value-only representation is accepted by the port. |
| `msm_public_points_hs` | Equal-length authenticated linear MSM: map value and MAC scalar components to their respective group sums using the same fixed public bases. |
| `scalar_mul_public_point_hs` | Same authenticated public-point map for both scalar components; separate G1/G2 types and strict admitted public point. |
| `add_assign_points_public_hs(id,...)` | Add a stock authenticated public-point constant using alpha context; retain both group components. |
| `open_two_half_points` | `open_checked_*`: flush field protocol checks **before opening**; stock group `POpen`, then group `Check` on every opened type, and field check again. Return no point/proof until every check succeeds. |

Exact stock multiplication signatures are `init_mul()`,
`prepare_mul(const T&,const T&,int=-1)`, `exchange()`,
`finalize_mul(int=-1) -> T`. `ProtocolSet<T>::check()` invokes both
`protocol.check()` and `output.Check(processor.P)`. `Preprocessing<T>::get_random()`
returns T and its default route sums fresh authenticated input masks from all
players. These are source interfaces; the custom prover has not exercised them.
[Beaver interface](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/Beaver.h#L59-L68),
[check composition](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/ProtocolSet.h),
[random preprocessing](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Processor/Data_Files.hpp#L47-L57).

## QAP/FFT and the H-query arity decision

Select **LibSnarkReduction only** for the first port and use a matching Arkworks
key. Do not switch to CircomReduction: it has different domains/query semantics
and two AB products. The selected path evaluates complete A/B/C rows, appends
the entire public prefix to A as the reference does, interpolates, shifts to a
coset, performs an authenticated AB product, subtracts C, divides by the public
vanishing value, interpolates again and reverses the shift. No C row, predicate,
wire, constant or auxiliary may disappear.

The C++ FFT adapter should reuse mcl's existing bit-reversal/butterfly algebra
but replace its BLS12-381-specific root initialization with an explicit pinned
plan from the Ark exporter. Check N is a power of two in Fr's supported range,
omega^N=1, omega^(N/2)!=1, N*invN=1 and coset_shift^N!=1. Bind exact root
orientation, normalization, input/output order and coset shift to the model.
Apply each pure linear transform to both local value and MAC lanes. Do not
call unmodified `mcl::Ntt<Fr>::init()` and hope roots agree. A pure Rust FFT FFI
using the existing Domain code on both lanes is an alternative if maintaining
that small explicit-root adapter proves less clear; choose one, not both.

There is an intentional reference arity difference: the selected LibSnark
map returns N coefficients, while Ark's H query has N-1 points. The locked
`taceo-groth16`0.2.1 source explicitly documents its shorter-slice MSM truncation
for that pair (`src/lib.rs:182–190`); Ark generator uses
`h_query_scalars(m_raw-1)` (`generator.rs:165–169`).

Make that algebra explicit: require H.len=N and original H-query.len=N-1;
derive a public query by appending **exactly one group identity**, then use an
equal-length authenticated MSM. Bind original key identity plus this fixed
padding policy. It gives the same tail-times-identity semantics as the reference.
Do not claim or open a zero H tail, guess arity from runtime slices, silently zip
unequal vectors, or accept arbitrary mismatches. Every other MSM requires exact
query/scalar count equality.

## Full proof operation order

After all parties agree the exact public model/key/matrix/statement/source
identity and external input mapping:

1. Ingest authenticated external inputs, derive cross-client auxiliary wires
   inside MPC, and assemble `[ONE, public..., private...]` with exact dimensions.
2. Run the authenticated LibSnark witness map to H. Sample fresh authenticated
   r,s independently; batch their product as stock MASCOT multiplication.
3. Compute authenticated A, B1, B2, L and H group accumulators using the exact
   public key queries. Add alpha/beta and public-input terms as authenticated
   public constants. Keep all scalar/group MACs.
4. Check field operations; open/check A and masked B1. Their early release is
   justified only by fresh hidden uniform proof masks and the matching protocol,
   not by an unauthenticated sum or final-verifier success.
5. Compute C = s*A + r*B1 - r*s*delta1 + L + H as authenticated group operations;
   check field state and open/check C and B2. All parties receive the same A/B2/C.
6. Strictly bridge public affine coordinates into Arkworks, verify against the
   exact VK/public input, and require identical complete proof bytes across
   all three parties. No debug opening of r,s,H,witness, alpha, sk or inv_k.

The formula is the selected co-snarks core, not a new primitive. The new
authentication/codec/input composition remains unqualified until implemented
and independently checked.

## Smallest meaningful full-proof gate

Use one new research circuit, future fresh toy parameters and two external
clients. No real note, old parameter key, NativeAuthSpend witness or KAS input.

```text
public instance: [ONE=1, t=128]
private: x=3 from client X, y=5 from client Y, z=x*y derived INSIDE MPC
constraints: x*y=z; (z+1)*(x+y)=t
columns: ONE,t,x,y,z
```

There are2 constraints,2 instance variables,3 private variables and5 total
variables. Domain N=4. A/B/C nonzero counts are3/3/2. A/B1/B2 queries have5
points, L has3, original H has3 and its derived padded query has4. Verify VK
IC count2. The final Ark verifier input is `[128]`, without the leading ONE.

This circuit has a nonzero H polynomial for the selected fixture. With domain
points 1,omega,-1,-omega, A evaluations are3,16,1,128 and B evaluations5,8,0,0.
Their leading interpolation coefficients cannot vanish for a primitive fourth
root in this large field; their product is nonzero. Thus H-MSM and the QAP
product/FFT path cannot be skipped as a trivial zero case. The exported plain
reference should freeze dimensions and expected public fixture before future
MPC execution; it is an oracle for public test data, never an input dealer.

Acceptance requires the real external-client route, actual checked MASCOT
operations, exact reference reduction/codec/key joins, all three complete
verified identical proofs and no private diagnostic export. A proof produced
from party0's clear combined witness is **not this gate**. Test wrong t=129
against the completed proof as a public verifier refusal control, alongside
pre-input wrong field/curve/arity/source and malformed-point refusals. Those
future benign correctness checks are not an active privacy experiment.

## Why this route, and what remains unavailable

The Rust alternative would require a new authenticated trait/module: replace
both half-share associated types, add immutable alpha context to public
constants, network/result threading through R1CSToQAP and every multiplication,
move network operations outside Rayon, expose an authenticated public proving
entry, and supply a MASCOT context rather than REP3/Shamir state. `MpcState`
also requires fork although this proving path does not use it; unsupported
forking must refuse rather than clone preprocessing. Keeping the old names
with raw Fr outputs would silently discard authentication. Adding C++ FFI to
that changed Rust surface also introduces canonical private-share/point bridges.

The recommended C++ port keeps the low-level protocol, owner sockets, MAC key,
shares and group checks in one backend. It ports a small fixed arithmetic
algorithm rather than maintaining the semi-honest driver abstraction. Its
additional mathematical surface is the reviewed explicit-root linear FFT
adapter and a public Arkworks exporter/verifier boundary. Neither route is
implemented here; compare actual source simplicity again when wrappers exist.

Still unavailable: BN254 group wrappers/strict codec, the custom MASCOT prover,
qualified external-input composition, frozen complete build closure, the full
proof gate, NativeAuthSpend/full-batch composition and actual independent
operators. Real owner mapping, amount/timing linkage and abort/retry privacy
remain separate blockers. No fee, native acceptance, production security or
general active-privacy claim follows. Selecting the backend/owner-input trust
boundary is an architecture decision and needs the project's ADR/documentation
work before substantial implementation; this source plan changes no such files.
