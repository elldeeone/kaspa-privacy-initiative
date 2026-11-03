# Corrupt-P1 finite source-assumption ledger

**Status:** candidate ledger, not selected, 2026-10-29. This document defines
the smallest finite assumptions found for the bounded P1 observer. It does not
assert that the executable is secure, that the capture is a complete physical
host image, or that payment privacy holds. `SELECTED_SOURCE_ASSUMPTIONS` must
remain empty until the v9 capture source, build, launch, actual receipt, and
model decoder are frozen together and the admission conditions below pass.

The retained build-16 receipt is evidence for the earlier fourteen-lane v7
source only. It is not a selectable receipt for the v9 scalar/query/group-state
closure.

## Decision

No individual authenticated share, MAC, random value, opening, or peer frame
is independently harmless. The only potentially defensible cryptographic
claim is about a **joint, source-enumerated view**, conditional on four named
families:

1. `A1-MASCOT-OT`: stock MP-SPDZ/MASCOT authenticated finite-field state and
   traffic, including an explicit assumption for the unresolved pinned base-OT
   composition;
2. `A2-DDNNT-5N`: external-owner input delivery and offset derivation;
3. `A3-MIXED-GROUP`: the two Smart--Talibi Alaoui scalar/G1 products and the
   authenticated group state used to compute them; and
4. `A4-GROTH16-FINAL`: the Ozdemir--Boneh Appendix-E completion and the
   standard final Groth16 proof distribution.

The dependency order is `A2 -> A1`, `A3 -> A1`, and `A4 -> A3 -> A1`. A field
may cite the whole required chain; citing only the last paper named at a call
site is insufficient.

Exact schema/build/role correspondence is a separate directly checked
prerequisite, `C0-CAPTURE-CORRESPONDENCE`. It is not a cryptographic theorem.
Timing, sizes, ordering, abort/retry history, internal uncaptured random tape,
and physical-host state are not absorbed into `A1`--`A4`.

## Frozen observer and corruption conditions

There are two distinct scopes. The cited protocol theorems use an active,
static malicious-computing-party model. The empirical gate selected by
[ADR-0088](../docs/adr/0088-passive-pinned-p1-empirical-observer-scope.md)
instantiates only the exact pinned, instrumented, protocol-following P1 process
plus C1's declared wallet view. The stronger theorem model may conditionally
explain recognized cryptographic values in that passive trace; it does **not**
turn the trace into the view of an arbitrary malicious binary or host.

Every candidate assumption below has all of these preconditions:

- For theorem applicability, P1 is statically corrupted before setup and P0/P2
  remain honest throughout the attempt. There is no adaptive/mobile
  computing-party corruption and no later recovery of an honest party's
  retained secrets.
- For empirical completeness, P1 follows the exact selected instrumented
  binary and schedule. A truly malicious host can add logs, copies, clocks,
  probes, or covert outputs absent from that binary. Those views remain
  explicitly outside the admitted empirical observer and unqualified for all
  general active-malicious or host-compromise claims.
- C1 is a corrupt external owner colluding with P1. C1's record, received data,
  chosen messages, local randomness, success/abort decisions, and prior
  knowledge are explicit adversarial auxiliary input. C1 is not counted as a
  second corrupt computing party.
- Compared owner mappings have the same corrupt-party/C1 input and auxiliary
  information, public statement and projection, circuit, dimensions, call
  schedule, declared public outputs, and admitted success/abort class. Any
  difference in those values is explicit leakage.
- Every key, input mask, DDNNT tuple, MASCOT tuple/triple, mixed-product triple,
  proof randomizer, OT state, attempt identity, and failed-attempt context obeys
  the source-required fresh/one-use lifecycle. A retry starts a new context;
  no failed state is resumed.
- Authenticated private channels, authenticated broadcast/agreement, TLS role
  binding, secure randomness, canonical field/point decoding, BN254 subgroup
  checks, hashes/PRGs, and the papers' primitive assumptions hold.
- All sacrifice, OT-correlation, scalar MAC, group MAC, broadcast/agreement,
  and final verification checks complete before a successful result is used.
  Messages sent before a later check and their abort traces remain part of the
  corrupt view.
- The exact selected local source implements the cited protocol
  correspondences. This is an explicit assumption, not a conclusion from
  passing controls.

MASCOT permits an active adversary to learn its ideal output first and then
abort. Therefore high-level abort is allowed leakage. Failure timing, the last
completed stage, partial byte counts, exception text, and retry linkage are not
thereby theorem-covered.

## Exact upstream source closure

The dependency authority is the local
[`DEPENDENCIES.json`](../poc/local-private-payment/mpc-prover/DEPENDENCIES.json).
Any different commit, compiler policy, patch, or runtime is a different
assumption preimage.

| Component | Exact pin | Files relevant to this ledger | Scope |
|---|---|---|---|
| MP-SPDZ | [`113c4e47dd94bca9ecab029d2f0abe649bea5c52`](https://github.com/data61/MP-SPDZ/tree/113c4e47dd94bca9ecab029d2f0abe649bea5c52) | [`Protocols/Share.h`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/Share.h), [`Protocols/MascotPrep.h`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/MascotPrep.h), [`Protocols/MascotPrep.hpp`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/MascotPrep.hpp), [`OT/NPartyTripleGenerator.hpp`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/OT/NPartyTripleGenerator.hpp), [`Protocols/Beaver.hpp`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/Beaver.hpp), [`Protocols/MAC_Check.hpp`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/MAC_Check.hpp), [`Protocols/ProtocolSet.h`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/ProtocolSet.h), [`OT/OTExtensionWithMatrix.cpp`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/OT/OTExtensionWithMatrix.cpp), and [`OT/BaseOT.cpp`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/OT/BaseOT.cpp) | Exact stock scalar share/MAC, live MASCOT preprocessing, online multiplication/opening/check, SoftSpoken adapter, and base-OT selection |
| SimplestOT_C | [`7ef7666909e493a18c99efe56f97cc4d13723005`](https://github.com/mkskeller/SimplestOT_C/tree/7ef7666909e493a18c99efe56f97cc4d13723005) | [`ref10`](https://github.com/mkskeller/SimplestOT_C/tree/7ef7666909e493a18c99efe56f97cc4d13723005/ref10) and [`README.md`](https://github.com/mkskeller/SimplestOT_C/blob/7ef7666909e493a18c99efe56f97cc4d13723005/README.md) | Base OT actually selected by `BaseOT.cpp`; not itself a proof of the required composition |
| libOTe | [`fe6b2ff82a976a5332b3a2efe325831588b1324a`](https://github.com/mkskeller/libOTe/tree/fe6b2ff82a976a5332b3a2efe325831588b1324a) | [`SoftSpokenMalOtExt.h`](https://github.com/mkskeller/libOTe/blob/fe6b2ff82a976a5332b3a2efe325831588b1324a/libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenMalOtExt.h), [`SoftSpokenMalOtExt.cpp`](https://github.com/mkskeller/libOTe/blob/fe6b2ff82a976a5332b3a2efe325831588b1324a/libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenMalOtExt.cpp), and [`SubspaceVoleMaliciousLeaky.h`](https://github.com/mkskeller/libOTe/blob/fe6b2ff82a976a5332b3a2efe325831588b1324a/libOTe/Vole/SoftSpokenOT/SubspaceVoleMaliciousLeaky.h) | Malicious SoftSpoken/VOLE implementation selected with `USE_KOS=0`, `USE_LIBOTE2=1` |
| cryptoTools | [`f70175e0cbd36b808475c0c1bbf585304e43d3d0`](https://github.com/mkskeller/cryptotools/tree/f70175e0cbd36b808475c0c1bbf585304e43d3d0) | Transitive libOTe primitives | Exact repository selected by `DEPENDENCIES.json`; pinned implementation dependency, not a new theorem |
| coproto / macoro | [`8dce3918b06c80dbcd65baeb899f1a694433f926`](https://github.com/ladnir/coproto/tree/8dce3918b06c80dbcd65baeb899f1a694433f926) / [`ee5fa61a9bc2e4cd4cdddea8d4a6485332e8d58e`](https://github.com/ladnir/macoro/tree/ee5fa61a9bc2e4cd4cdddea8d4a6485332e8d58e) | Transitive libOTe transport/coroutine dependencies | Build closure only |
| function2 | [`02ca99831de59c7c3a4b834789260253cace0ced`](https://github.com/Naios/function2/tree/02ca99831de59c7c3a4b834789260253cace0ced) | Transitive callback dependency | Build closure only |
| libdivide | [`v5.2.0`](https://github.com/ridiculousfish/libdivide/tree/v5.2.0), one-file SHA-256 `4accff7e...03ec903` | Integer-division implementation dependency | Build closure only |
| mcl | [`9f49ba06593e2d426ab6fb9b0e17bc125a6f720c`](https://github.com/herumi/mcl/tree/9f49ba06593e2d426ab6fb9b0e17bc125a6f720c) | BN254 Fr/G1/G2 representation and operations | Exact curve implementation dependency, not a proof of canonical/subgroup use |

The selected configuration is MASCOT over BN254 Fr with malicious SoftSpoken,
`USE_KOS=0`, `USE_LIBOTE2=1`, `AVX_OT=0`, assertions enabled, and neither
`INSECURE` nor `NDEBUG`. The sole listed local MP-SPDZ patch tightens the
external-client certificate requirement; it does not change MASCOT arithmetic.

The manifest additionally pins archive SHA-256 values for MP-SPDZ,
SimplestOT_C, libOTe, cryptoTools, and mcl, plus the exact local GMP and
libsodium development-package versions and hashes and compiler version. Those
binary/package pins are build correspondence, not primary-source security
proofs. `A1` still assumes correct Ristretto/libsodium, GMP, OpenSSL/TLS,
hash/PRG, compiler, loader, and linked-library behavior. A selectable v9 build
receipt must bind the actual linked closure; the old v7 build-16 receipt cannot
supply it.

The papers are pinned by report and inspected revision/scope:

- Keller, Orsini, Scholl, [MASCOT, ePrint 2016/505, Sections 2--6,
  Theorems 2--5 and Corollary 1](https://eprint.iacr.org/2016/505);
- Roy, [SoftSpokenOT, ePrint 2022/192, Section 2.3 and Theorem
  5.1](https://eprint.iacr.org/2022/192), archive revision 2025-11-18;
- Chou and Orlandi, [SimplestOT, ePrint 2015/267, revised Section
  1.1](https://eprint.iacr.org/2015/267), archive revision 2018-05-29;
- Damgaard et al., [DDNNT client input, ePrint 2015/1006, Section 3.1,
  Figures 1--2 and Lemma 1](https://eprint.iacr.org/2015/1006);
- Smart and Talibi Alaoui, [scalar/group multiplication, ePrint 2019/768,
  Figure 9 and Theorem 2](https://eprint.iacr.org/2019/768), archive revision
  2022-12-01;
- Ozdemir and Boneh, [collaborative Groth16, ePrint 2021/1530, Appendix E and
  E.1](https://eprint.iacr.org/2021/1530), archive revision 2022-07-16; and
- Groth, [the three-element pairing SNARK and zero-knowledge
  construction](https://iacr.org/archive/eurocrypt2016/96650272/96650272.pdf),
  EUROCRYPT 2016.

## A1-MASCOT-OT

### Theorem scope

MASCOT Theorems 2--5 compose authenticated sharing, triple/input-tuple
preprocessing, and the arithmetic black box against a malicious **static**
adversary corrupting up to `n-1` computing parties in the stated hybrids. The
online simulator covers honest input masks and one-use Beaver openings, while
the ideal functionality exposes intended openings/outputs and permits abort.
This supports a joint-view statement, not mutual independence of its fields.

SoftSpoken Theorem 5.1 proves its malicious OT extension in the paper's
malicious-VOLE-pre hybrid, on authenticated channels, with its stated
hash/PRG-style assumptions and selective-abort leakage. It does not by itself
prove MP-SPDZ, SimplestOT, or their composition.

The revised SimplestOT Section 1.1 expressly withdraws the earlier UC claim and
only informally discusses using an OT extension for timely decryption. Thus
`A1` must contain this separate proposition:

> The exact pinned SimplestOT_C -> libOTe malicious SoftSpoken -> MP-SPDZ
> MASCOT stack securely realizes the ROT/VOLE and authenticated-share hybrids
> used in MASCOT for this configuration.

That proposition is an admitted assumption if selected. It is not a theorem
conclusion of the inspected sources.

### Covered joint state

Subject to `C0`, `A1` may jointly cover P1's local Fr share/MAC values, local
MAC-key share, MASCOT input tuples/triples/randoms, recognized stock finite-
field masked openings, scalar MAC-check state, and the precisely attributed
OT/preprocessing/finite-field peer messages. It does not cover custom owner or
group composition merely because those values use `Share<Fr>`.

### Additional applicability conditions

- every tuple/triple is fresh and consumed once;
- one fresh MAC-key/OT lifecycle is used, never resumed after failure;
- the field satisfies the MASCOT paper's parameter hypotheses;
- amplification, sacrifice, correlation, commitment/broadcast, and output
  checks execute exactly as pinned; and
- no peer frame outside the enumerated stock call sites is assigned to `A1`.

## A2-DDNNT-5N

### Theorem scope

DDNNT Section 3.1 delivers additive value shares of `(s,r,w,v,u)`, with
`w=s*r` and `u=v*r`, to the client. The client reconstructs and checks both
relations, then sends the common `d=x-s`; servers derive `[x]=[s]+d`. Lemma 1
gives the paper's input-security bound: malicious servers can make an honest
client accept a changed value only with probability at most `1/p`, while abort
remains possible.

This covers the exact five-value protocol only. It does not cover the removed
three-value `x+a` adapter or the unselected additive-stock-input proposal.

### Local correspondence and covered joint state

The exact local files are
[`owner_input_ddnnt.hpp`](../poc/local-private-payment/mpc-prover/owner_input_ddnnt.hpp),
[`owner_input_ddnnt.cpp`](../poc/local-private-payment/mpc-prover/owner_input_ddnnt.cpp),
[`owner_inputs_active.hpp`](../poc/local-private-payment/mpc-prover/owner_inputs_active.hpp),
and
[`owner_inputs_active.cpp`](../poc/local-private-payment/mpc-prover/owner_inputs_active.cpp).
`A2` may cover the joint owner preprocessing-share frame, common offset frame,
associated authenticated scalar state, and exact DDNNT agreement traffic only
when those hashes appear in the final source/build manifest.

### Additional applicability conditions

- one independent fresh tuple per field, exact field-major `s,r,w,v,u` order;
- only value shares go to owners; MAC shares stay local;
- both owner equations pass before any `d` is emitted;
- all servers receive and agree on identical exact `d` bytes before canonical
  Fr decoding and derivation;
- exact `5N` outbound and `N` inbound framing, private authenticated TLS, and
  strict role/contract binding; and
- every malformed, disagreeing, replayed, partial, or failed exchange poisons
  the context and requires a fresh attempt.

C1's own frame contents are auxiliary input, not honest-owner leakage hidden by
`A2`.

## A3-MIXED-GROUP

### Theorem scope

Smart--Talibi Alaoui Figure 9 maps a fresh SPDZ field triple `(a,b,c=ab)` to a
scalar/group triple and opens one uniformly masked scalar difference and one
uniformly masked group difference. Theorem 2 proves the online elliptic-curve
functionality with abort in the SPDZ-offline hybrid for a prime-order group and
a full-threshold active adversary.

The local label swap is algebraically equivalent: for each product `x*Q`, it
uses `U=aG`, scalar mask `b`, `V=cG`, opens `D=Q-U` and `e=x-b`, then derives
`V+eU+bD+eD=xQ`. Exactly two independent triples compute `s*A` and
`r*B1_base`.

### Local correspondence and covered joint state

The exact local files are
[`auth_groups.hpp`](../poc/local-private-payment/mpc-prover/auth_groups.hpp),
[`auth_groups.cpp`](../poc/local-private-payment/mpc-prover/auth_groups.cpp),
[`bn254_values.hpp`](../poc/local-private-payment/mpc-prover/bn254_values.hpp),
and
[`bn254_values.cpp`](../poc/local-private-payment/mpc-prover/bn254_values.cpp).

The candidate v9 capture must directly record, in canonical algebraic order:

- G1 `BASE`: `A,B1_base,L,H`;
- G2 `BASE`: `B2`;
- G1 `MIXED`: `U0,V0,D0,U1,V1,D1`;
- G1 `PRODUCTS`: `sA,rB1base`; and
- G1/G2 `FINAL`: `A,C` / `B2` immediately before opening.

`BASE` order is a frozen algebraic serialization order; it is not a claim that
all selected sources construct `L` before `H`. Every captured authenticated
group object contains P1's local value share and MAC share. Repeated `A` and
`B2` must be byte-equal across stages.

This closes the finite **named application-level mathematical group state** if
the exact call sites and counts pass. Query/MSM worker partials, expression
temporaries, group-checker internals, allocator copies, and physical memory are
not directly captured. Deterministic mathematical derivation of the former
requires a separately enumerated source correspondence; residual host state
remains unqualified.

### Additional applicability conditions

- BN254 Fr is exactly the order of the admitted G1 subgroup; all encodings are
  canonical, on-curve, and in the required subgroup;
- the group share/MAC representation uses the same authenticated scalar-key
  semantics as the paper's SPDZ-offline hybrid;
- the two field triples are fresh, independent, and one-use;
- scalar pending checks, group `Direct_MC` checks, and broadcast/agreement all
  complete; and
- any failure poisons the context before a proof can be returned.

The paper does not cover G2 local state used only by linear construction and
final opening as a separate mixed multiplication. Its deterministic linear
correspondence and group MAC/opening implementation must therefore be included
explicitly in the `A3` source preimage.

## A4-GROTH16-FINAL

### Theorem scope

Ozdemir--Boneh Appendix E/E.1 gives the collaborative decomposition

```text
A       = alpha1 + A-query + r*delta1
B2      = beta2  + B2-query + s*delta2
B1_base = beta1  + B1-query
C       = s*A + r*B1_base + L + H.
```

It needs exactly the two `A3` products and opens only the three standard
Groth16 proof elements `(A,B2,C)`. Raw auxiliary `B1` is absent. The original
Groth16 construction establishes zero knowledge for the witness through that
standard three-element proof under its CRS and bilinear-group security model.

### Local correspondence and covered joint state

The exact local completion files are
[`auth_groth16.cpp`](../poc/local-private-payment/mpc-prover/auth_groth16.cpp),
[`financial/packed_groth16.cpp`](../poc/local-private-payment/mpc-prover/financial/packed_groth16.cpp),
[`financial/financial_prover.cpp`](../poc/local-private-payment/mpc-prover/financial/financial_prover.cpp),
and
[`proof_codec.cpp`](../poc/local-private-payment/mpc-prover/proof_codec.cpp).

`A4` may cover only the nonliteral witness implications of final `A,C` and
`B2`, jointly with `A3`, when the exact public proof bytes bind to the released
projection and independently verify. Literal equality to the public proof is a
direct constraint, not an assumption.

### Additional applicability conditions

- a valid, correctly generated CRS with no adversarially retained toxic waste;
- fresh independent proof randomizers with the distribution required by
  Groth16;
- the selected relation and public statement bind the intended complete
  record, and independent verification checks the exact released proof;
- no auxiliary witness-dependent group point is opened or exported; and
- only the selected durable `FinancialValidatedAssignment` can mint the
  context/generation/failure-epoch-bound `FinalGroth16CaptureAuthority`; the
  checked `GroupMacSetup` opener refuses a tokenless call whenever capture is
  attached and uses a second exact-state permit around the checked opening.
  A generic group-opening alias is not admissible.

`A4` does not cover malformed/invalid proof attempts, which remain visible as
abort/partial transcripts, or any timing/host side channel.

## Per-field disposition

The following table maps all 36 base `unmodeled_fields` in the v9
`corrupt_server` model. The C03 authority parser directly constrains five
binding/grammar rows and now recomputes three authenticated-group equation
families from the captured share/MAC lanes, leaving 28 nonliteral or empirical
rows before any source assumption is selected. `CANDIDATE A*` means
the exact assumption chain could be selected after admission; it does not mean
selected today.

| Model field | Required disposition | Exact boundary |
|---|---|---|
| `capture.model_preimage_binding` | `DIRECT C0` | HELLO bytes `236:268` must equal the exact sealed financial-model preimage identity before any selected query computation. This binds identity only, not nonliteral privacy. |
| `capture.public_query_preimage_binding` | `DIRECT C0` | HELLO bytes `268:300` must equal the exact sealed query-store transport/preimage identity. Query correctness and hiding are separate. |
| `capture.scalar_callsite_manifest_binding` | `DIRECT C0` | HELLO bytes `300:332` must equal scalar-manifest SHA-256 `5e6903569bc71cbfb5549b369b79a19ecda6686dc4ab25fca0d161c6e1527b6b`. |
| `records[scalar-capture-binding].site_kind_element_count_order` | `DIRECT C0` | Semantic 17 is exact atomic 16-byte `v1/kind/site/count/zero4`, selected sites `1..22`, randomness exactly `{1,7,20,21}`, followed by matching share and MAC widths, with complete bitmap `0x3fffff`. |
| `records[scalar-capture-binding].payload.nonliteral_implications` | `UNQUALIFIED-MIXED` today; candidate `A1` plus the source-proven application family | Site labels and counts identify provenance but do not make the following share/MAC values independently simulatable. Each site must map to DDNNT, stock field, mixed-group, or proof logic; unknown/new sites fail closed. |
| `records[mascot-message].payload.nonliteral_implications` | `UNQUALIFIED-MIXED` today; candidate split below | One generic semantic mixes several protocol families and unknown/control traffic. Never attach a blanket “MASCOT secure” digest. |
| `records[field-opening].payload.nonliteral_implications` | `UNQUALIFIED-MIXED` today | Split declared public outputs (`DIRECT`), stock scalar masked openings (`A1`), A3 scalar differences (`A1+A3`), and unknown call sites (`UNQUALIFIED`). |
| `records[masked-field-intermediate].payload.nonliteral_implications` | `CANDIDATE A1+A3` | Exactly two fresh mixed-product scalar differences; exact arity/callsite required. |
| `records[masked-g1-intermediate].payload.nonliteral_implications` | `CANDIDATE A3` | Exactly two fresh mixed-product group differences; exact arity/callsite required. |
| `records[final-proof-g1].payload.nonliteral_implications` | `CANDIDATE A1+A3+A4` | Only final `A,C`; literal public-proof equality is direct. |
| `records[final-proof-g2].payload.nonliteral_implications` | `CANDIDATE A1+A3+A4` | Only final `B2`; literal public-proof equality is direct. |
| `wire.frames[].monotonic_ns` | `UNQUALIFIED / EMPIRICAL` | Observed clock/scheduling signal; freeze as an observer feature. No cited theorem covers it. |
| `wire.frames[].payload_length` | `UNQUALIFIED / EMPIRICAL` | Public-shape-determined lengths may be directly explained; partial/failure lengths remain mapping-sensitive empirical leakage. |
| `wire.frames[].sequence_message_chunk_order` | `UNQUALIFIED / EMPIRICAL` | Directly observed execution/progress schedule, not theorem-covered. |
| `wire.frames[].direction_peer_fork` | `UNQUALIFIED / EMPIRICAL` | Direct topology/fork metadata. Public expected topology can be constrained; deviations and timing remain empirical. |
| `wire.frames[].mixed_protocol_nonliteral_implications` | `UNQUALIFIED-MIXED` today | Requires the closed peer-family partition below; no generic cryptographic citation covers the mixed lane. |
| `attempt.abort_retry_partial_transcript` | `UNQUALIFIED / EXPLICIT LEAKAGE` | A1--A4 allow high-level abort, not detailed failure phase, partial transcript, retry count, or cross-attempt link. |
| `capture.source_build_launch_role_binding` | `DIRECT C0` | Exact authority/source/build/launch/role join; never a cryptographic assumption. |
| `records[owner-input-offset].payload.nonliteral_implications` | `CANDIDATE A1+A2` | Joint DDNNT `d=x-s` view; exact common-byte agreement and freshness required. |
| `records[owner-input-preprocessing-share].payload.nonliteral_implications` | `CANDIDATE A1+A2` | Joint local value shares of exact `s,r,w,v,u`; never five independent claims. |
| `records[authenticated-share].payload.nonliteral_implications` | `CANDIDATE A1` plus source-proven application family | Generic scalar state must be attributed to DDNNT (`A2`), mixed group (`A3`), or stock field computation; unknown call sites remain unqualified. |
| `records[mac-key-share].payload.nonliteral_implications` | `CANDIDATE A1` | One P1 local alpha share for the exact fresh lifecycle; not the global key. |
| `records[mac-share].payload.nonliteral_implications` | `CANDIDATE A1` plus source-proven application family | Joint with its value share/key/transcript; never independently random. |
| `records[randomness-share].payload.nonliteral_implications` | `CANDIDATE A1` | Recognized fresh MASCOT random authenticated values only. |
| `records[randomness-mac].payload.nonliteral_implications` | `CANDIDATE A1` | Joint with the corresponding random share and key. |
| `records[authenticated-g1-state].payload.nonliteral_implications` | `CANDIDATE A1+A3+A4` | Exact BASE/MIXED/PRODUCTS/FINAL staged objects and equality constraints only. |
| `records[authenticated-g2-state].payload.nonliteral_implications` | `CANDIDATE A1+A3+A4` | Exact BASE/FINAL `B2` state and equality constraint only. |
| `records[authenticated-group-query-msm-temporary].capture_correspondence` | `CONDITIONAL-DERIVATION` for named mathematical values; otherwise `UNQUALIFIED-UNCAPTURED` | Requires exact source/evaluation correspondence. Memory copies, worker residue, and checker internals are not directly captured in v9. |
| `records[authenticated-group-query-msm-temporary].compressed_query_bytes` | `CANDIDATE SOURCE-CORRESPONDENCE`, but `UNMODELED` today | Bound query-store preimage and exact decoder source may determine these bytes mathematically; they are not a direct capture lane. |
| `records[authenticated-group-query-msm-temporary].decoded_public_point_chunks` | `CANDIDATE SOURCE-CORRESPONDENCE`, but `UNMODELED` today | Requires canonical decoding/subgroup checks and exact chunk schedule from the sealed query store; no theorem makes a parser implementation implicit. |
| `records[authenticated-group-query-msm-temporary].point_map_share_mac` | `CANDIDATE A1+A3+A4 SOURCE-CORRESPONDENCE`, but `UNMODELED` today | Requires executable reconstruction from captured scalar share/MAC lanes and public points under the exact local linear map. |
| `records[authenticated-group-query-msm-temporary].worker_partials` | `CANDIDATE A1+A3+A4 SOURCE-CORRESPONDENCE`, but `UNMODELED` today | The deterministic worker-reduction source can define mathematical partials, but physical worker memory/scheduler residue is excluded and unqualified. |
| `records[authenticated-group-query-msm-temporary].running_query_sums` | `CANDIDATE A1+A3+A4 SOURCE-CORRESPONDENCE`, but `UNMODELED` today | Requires exact reduction order and captured scalar/query correspondence. No selected assumption currently supplies it. |
| `records[authenticated-g1-state].D_equals_Q_minus_U` | `DIRECT CONSTRAINT` for the captured equation; privacy still candidate `A3` | The model recomputes both share and MAC equations from typed BASE/MIXED state. This proves literal algebraic correspondence only, not simulation or triple security. |
| `records[authenticated-g1-state].beaver_product_equations` | `DIRECT CONSTRAINT` for the captured equation; privacy still candidate `A1+A3` | The model recomputes both product share/MAC formulas using site-22 triple lanes and the opened differences. Fresh valid triples and hiding remain assumptions. |
| `records[authenticated-g1-state].C_equals_products_plus_L_plus_H` | `DIRECT CONSTRAINT` for the captured equation; privacy still candidate `A3+A4` | The model recomputes the FINAL share/MAC equation. Exact Appendix-E construction, proof ZK, and simulation remain conditional. |

All `literal_public_identifiers`, exact record grammar, exact lane counts and
widths, repeated-stage byte equality, projection bytes, and source/build/role
identities remain direct constraints. They must not consume an assumption
digest.

The following are not `ARTIFACT_LEAKAGE_FIELDS` in the bounded empirical
observer. They are exact fail-closed boundary-receipt values under
`inventory.out_of_scope_unqualified_boundaries.boundaries`, with
`modeled_or_harmless=false` and
`blocks_general_active_or_host_claims=true`:

| Boundary receipt value | Disposition |
|---|---|
| `P1_INTERNAL_OT_PRNG_RANDOM_TAPE` | Uncaptured and unqualified. A1 does not establish that the artifact contains P1's base-OT/VOLE/PRNG coins or seeds. |
| `ARBITRARY_MODIFIED_OR_MALICIOUS_HOST_OR_BINARY` | Outside the pinned passive-process experiment and unqualified for any active-malicious claim. |
| `HOST_MEMORY_LOG_SWAP_CACHE_PAGE_SCHEDULE_CPU_GPU_STATE` | Outside the admitted empirical view and unqualified for host-compromise or physical-side-channel claims. |
| `COVERT_AND_NETWORK_STACK_CHANNELS` | Application plaintext capture does not contain TLS records, TCP/IP packetization, kernel/NIC state, or a malicious covert channel. |

## Required peer-transport split

The current `mascot-message` lane is too coarse for a selected field-level
ledger. The final schema or independent decoder must partition every peer
message into this closed enumeration:

| Peer family | Candidate coverage | Required source attribution |
|---|---|---|
| base OT, malicious SoftSpoken/VOLE, MASCOT generation/sacrifice | `A1` | Exact `BaseOT`, `OTExtensionWithMatrix`, libOTe, and MASCOT generator call sites |
| stock finite-field multiplication, opening, MAC/broadcast checks | `A1` | Exact Beaver/MAC-check call sites and batch/arity |
| DDNNT offset length/byte agreement and poisoning | `A1+A2` | Exact owner-input call sites; owner TLS frames stay separate |
| mixed scalar opening, G1 opening, scalar/group MAC checks | `A1+A3` | Exactly two products and their checked opening sequence |
| final `A,C,B2` opening/agreement/public proof bytes | `A1+A3+A4`, with public equality `DIRECT` | Capability-bound final-completion call site only |
| setup/control/error/unknown or any new call site | `UNQUALIFIED` | Schema change; fail closed |

If frames cannot be partitioned unambiguously from captured callsite/phase
tags, the generic nonliteral peer row must remain unqualified. An alternative
single composite digest is admissible only if it enumerates **every** possible
peer call site and exact sequence in the selected binary; it may not be a
generic MASCOT citation.

## C0-CAPTURE-CORRESPONDENCE admission

Before any `A*` digest can be selected, direct controls must establish:

1. one exact v9 source manifest with hashes for every local source/header,
   upstream pin, patch, build policy, linked object/library, decoder, and
   assumption document;
2. exact P1 role, three-party roster, fixed descriptor, attempt/cohort/run
   identity, source/build/launch digest, closed producer counts, and no unknown
   records;
3. all seventeen expected semantics, exact per-lane count/bytes/order, exact
   stage tags, complete owner bitmaps, and footer v9/count 17/496-byte size/
   instrumented mask `0x1ffff`, with no complete footer after partial capture;
4. HELLO's exact financial-model and query-store preimage identities, scalar
   callsite-manifest hash, semantic-17 `v1/kind/site/count/zero4` records,
   sites `1..22`, randomness sites `{1,7,20,21}`, and complete scalar bitmap
   `0x3fffff`, each bound atomically to its following share/MAC lanes, plus the
   source-manifest-bound query/MSM correspondence manifest
   `7cd5956c8a30da0d9bf2e040b1d67b83ffd516a211aba8d08985c6ecdae13ace`;
5. direct authenticated G1/G2 share+MAC capture at BASE, MIXED, PRODUCTS, and
   FINAL, including repeated `A/B2` equality and exact source callsites;
6. a nonforgeable boundary proving only the checked Appendix-E completion can
   emit final-proof openings, plus a static negative control proving no raw
   `B1` reaches `POpen`, capture, proof encoding, or output; and
7. an actual registered producer/model receipt from that exact build. Focused
   source tests and old build-16 runs are not substitutes.

The selected assumption preimage must be canonical machine-readable data. For
each `A1`--`A4` it must include: identifier/version; paper report/revision and
theorem/figure/section; exact upstream commits/files; exact local file hashes;
configuration/build/runtime digests; corruption and auxiliary-input model;
covered field paths and peer families; dependency assumption IDs; freshness,
channel, check, abort, and retry conditions; exclusions; and this document's
digest. A model field points to that exact digest. A human label is not
authority.

## Intrinsic stop rule

Even after `A1`--`A4` and `C0` are admitted, the result is only a conditional
bounded application-level corrupt-P1 model. It must continue to report these
as unqualified unless a later reviewed architecture decision explicitly
excludes them from the threat model or captures/models them:

- P1 internal OT/VOLE/PRNG random tape and uninstrumented protocol objects;
- query/MSM/checker/allocator residues not deterministically closed by the
  selected source manifest;
- physical memory, logs, swap, core dumps, caches, page faults, scheduler and
  CPU/GPU state;
- TLS/TCP/kernel/NIC packetization and metadata outside the application
  wrapper; and
- detailed abort/failure phase, timing, sizes, ordering, and retry linkage.

Silently narrowing “corrupt P1” to “the seventeen captured application lanes” is
not permitted. If the frozen threat model intends that narrower observer, it
needs an explicit ADR and corresponding claim language. Until then these rows
remain visible blockers, not zero-leakage assumptions.

