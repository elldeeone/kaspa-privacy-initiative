# Fixed native Output Groth16 adapter: frozen experiment 01

2026-10-26. Frozen before adapter implementation. Source assessment:
`NATIVE-G16-AGGREGATE-BACKEND-FEASIBILITY-01.md` SHA
`e05b2682984f1f220dd808821c34b673c64ea1b38ae7eb730c4f3611ba211e40`,
companion SHA `b255eac3d31467c8c8710cbb5496e2f14463eb19c8aa7895a46f3c08db946e7b`.
ADR: `docs/adr/0071-fixed-role-native-g16-adapter-experiment.md`.

## Question and fixed inputs

Does one fixed-role outer constraint system verify the existing native Output
proof while binding its exact canonical compressed bytes and its exact
Output168/SHA256/two-LE128 statement? This is not a privacy experiment.

The existing public fixture was extracted without new setup/proving:

| Input | Bytes | SHA256 |
| --- | ---: | --- |
| `FIXTURE.json` | 4642 | `3902034455441a53848ec5f516ba75d796373e7bb9a648fda53fcd97e545455b` |
| `fixtures/output-statement.bin` | 168 | `d3a607b2819b2b1585f5670ea1c31ffafc64386f1570b2f1ba94f3767db3a71a` |
| `fixtures/output-proof.bin` | 128 | `b49cd3145cb8a0d906addb0ca0be435c57d0836f15feb4d60002f6febb0937d7` |
| `fixtures/output-vk.bin` | 328 | `2839d491047edd5664db65af3fa92a7194d959e7f94f723eac982aa918c785e6` |

The original projection is the explicitly known-public-seed
`wallet-component-fixture-01/01-PAYMENT.bin`, 4077 bytes, SHA
`34066b48b32971a06fe60e264a4a60e7be3ed2643c5159258c271c9ddef8cf4a`.
Output row0 starts at byte725 and has 520 bytes. Current Output manifest is
`c400914d0b68c8f7846c198fd462210b35212f3e893f1f7801c457ad0069d729`.
The original result is explicitly `KNOWN_PUBLIC_SEEDS_SUPPLIED_CONTEXT_ONLY`;
Native Full, testnet, outer proof and privacy claims are false. Its low fee is
irrelevant to this component-only experiment and cannot be promoted into a
financial acceptance claim.

The unchanged native reference CLI, SHA
`e516b30b18d057c48fc68aefcd3268715f1cb622d94fb9b0fca9c5119ec2e463`,
returned `verified:true` for these exact three inputs. All11 selected relation
source files were guarded-read and concatenated in the source-defined order;
SHA `82cf9c59c17c006f79faf2b7689d09690ad505b776f9ce6409f4d1f9ccc79e5c`
matches both its selection and role manifest. The fixture manifest contains
each member. No PK body or private witness was opened.

## Intended circuit boundary

One Output wrapper only. Public inputs are the exact statement168 bytes and
proof128 bytes. Private variables are the mathematical proof A/B/C coordinates
and the inner two-element public witness. The selected VK is embedded as
compile-time constants, never witness- or caller-selected. Dynamic proof B has
no precomputed `Lines`; precomputation is allowed only for the fixed VK.

Use gnark commit `0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46`, module version
`v0.16.5-0.20261024231818-0be5c2ff3dbb`, with its pinned gnark-crypto
`v0.22.1-0.20261009142911-8911ee45d22b`. The exact Go toolchain is1.26.8.
Do not replace gnark's sum-pinned dependency graph or current native keys.

The wrapper must constrain:

1. All public bytes to8 bits; exact Output tag and domain; SHA256 of all168
   bytes; digest bytes0..16 and16..32 interpreted separately little-endian,
   each below2^128, equal to the two inner public inputs.
2. Original private Fq coordinate limbs to canonical integer range BEFORE
   canonical-bit conversion. `ToBits`/`Reduce` alone and modular equality are
   insufficient. Use established `AssertIsInRange`, `ToBitsCanonical`, binary
   comparison and byte gadgets. Never pack an Fq integer into one native Fr
   variable for a comparison.
3. Native proof encoding by canonical RE-ENCODING of private coordinates:
   A32 | B.x.c0LE32 | B.x.c1LE32 | C32. Ark sign is y>−y, not parity. Flags
   POSITIVE=0, INFINITY=0x40, NEGATIVE=0x80;0xc0 is invalid. Native A/B/C are
   nonidentity, so flag bit6 must0 at bytes31/95/127. B byte63 is an ordinary
   canonical Fq payload byte, with no flags. For Fq2, sign compares c1 first,
   then c0 only if c1 is zero. Every reconstructed byte equals its public byte.
4. Proof on-curve/subgroup membership using `WithSubgroupCheck`, and explicit
   nonidentity A/B/C. Use complete arithmetic as supplied by this exact gnark
   version; do not assume optional subgroup checks imply nonidentity or byte
   binding. Standard Groth16 verification under the constant Output VK must
   actually be constrained.

Host conversion may use checked established group parsers to create an initial
assignment, but it is never authority for a circuit acceptance. The independent
original native CLI is the byte-verification differential reference. Gnark's
own marshal bytes are not the Ark wire format.

## Actual constraint checking and finite negative criteria

Compile a real R1CS and invoke the compiled system's solver for the complete
assignment. An interpreter-only `test.IsSolved`, a host verifier flag, a panic,
or a witness-generator assertion is not the required result. Record solver
unsatisfaction separately from hint, input conversion, parse and process errors.
No outer setup or proof generation is needed. Reuse a compiled system for cases
with the same shape; do not compile a full pairing verifier per negative.

First use small encoding-only compiled controls for field/sign/range behavior.
They exercise the reusable codec helper, NOT Groth16 verification. Field-only
cases do not claim their arbitrary coordinates are valid curve points. Full
Output cases then use the genuine selected proof and complete verifier.

| Case group | Frozen expected result |
| --- | --- |
| Existing genuine Output proof/statement/VK | Complete Output R1CS ACCEPT. |
| Public proof byte0 XOR1 with ALL private pairing coordinates unchanged | Complete Output R1CS REJECT; pass changed public bytes directly to the assignment without host proof decoding. This is the priority decisive control. |
| Public A sign flip at31; infinity flag at31; invalid0xc0 flags; B payload byte63 high bit; B c0/c1 byte-half exchange | Complete Output R1CS REJECT with original private coordinates. Record native parser/refusal separately; never count it as the outer rejection. |
| A private x changed while original public bytes remain fixed | Complete Output R1CS REJECT. Assign raw limbs directly rather than normalizing through `ValueOf`. |
| A/B/C identity representations | Complete Output R1CS REJECT under explicit nonidentity policy. If an identity byte fixture is canonical, it still must not pass the native nonidentity policy. |
| Public CFhash byte in statement changed, original proof retained | Complete Output R1CS REJECT. |
| Private inner limb0 changed by1; two limbs exchanged; limb0 plus2^128 | Complete Output R1CS REJECT. These are statement/hash-binding checks, not stand-alone proofs of all range semantics. |
| Wrong public Output tag or D, with original proof | Complete Output R1CS REJECT. |
| Field codec x=1/generator point(1,2), matching bytes | Encoding-only R1CS ACCEPT; valid point claim only for the explicit generator. |
| Original raw Fq limbs encoding q+1 but public bytes encode1; raw q; spilled limb2^64 | Encoding-only R1CS REJECT by actual constraints; never normalize these assignments through `ValueOf` first. |
| Raw canonical q−1 with matching field-only bytes | Encoding-only R1CS ACCEPT; no curve-point/G16 claim. |
| Public byte256 or−1 | Encoding-only R1CS REJECT, not a host byte-conversion error; use a field-valued assignment bypassing a uint8 constructor. |
| Fq2 c1=0 and c0 on each side of the half-modulus; nonzero c1 with opposite c0 sign | Encoding-only R1CS ACCEPT for correct c1-first sign and REJECT for the independently wrong sign byte. Do not use c0-first ordering or parity. |
| Truncated/extended proof, invalid host-format input | Host/parser REJECT only; list separately and do not inflate compiled-constraint counts. |

The constant VK must have no witness/CLI replacement path. A host admission
control rejecting a substituted VK is evidence of that boundary, not a separate
recursive verification under an arbitrary key. Spend and the six-proof aggregate
are out of this run's scope.

## Execution and retention

Code is isolated under this experiment, not the live financial source family.
Source/fixture reads use unchanged helper09. No Original, actual owner material,
STATE/PLAN, campaign profile, controller log, private route or model truth is an
input. All fixture witnesses are explicitly public. Preserve the first unexpected
result, exact source/compiled-system identities and complete small result record.
Any correction requires a prospective new source/result identity; no retuning
of these expected verdicts or replacement setup/proof is permitted.

Root separately authorized <=1GB source/tool preparation in owned tmpfs.
No compile starts until its actual source/dependency bytes and current RAM/tmpfs
headroom are reported and Root coordinates the optional compile resource window.
Use a modest serial/low-parallelism worker; record actual peak resources without
extrapolation. These optional limits never affect live-trial acceptance.

Success means only the tested fixed Output adapter/constraint behavior. It does
not establish outer proof soundness, full native aggregate validity, malicious
MPC, financial privacy, ciphertext spendability, current-state acceptance,
independent recovery, fees or current-native2/4 compatibility.
