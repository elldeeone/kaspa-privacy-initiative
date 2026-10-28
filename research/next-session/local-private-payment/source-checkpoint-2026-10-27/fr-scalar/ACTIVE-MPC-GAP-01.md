# Active MPC proving: concrete reuse and remaining gaps

2026-10-27. Source research only. No compiler, MPC, witness, setup, proof,
Original, wallet, financial or attack experiment was executed. The frozen
publication candidate and its 489 selected files are unchanged.

**Recommendation:** reuse stock MP-SPDZ MASCOT for a new, explicitly BN254-Fr
scalar component first. Reuse its existing authenticated elliptic-curve opening
pattern for later BN254 group work. There is no qualified, drop-in
MASCOT-to-co-Groth16 bridge in the inspected code.

## What the selected implementations actually promise

| Component | Inspected guarantee/interface | Consequence |
| --- | --- | --- |
| co-snarks `436f63fa17f2f10ece38c6650df68da99fbc0307` | REP3 Groth16 explicitly documents one **semi-honest** corruption; Shamir documents threshold semi-honest corruption. | A coordinator with no MPC shares plus one passive prover fits that count; a coordinator operating another prover makes two corrupt parties and exceeds three-party REP3's threshold. Active privacy is not established. |
| MP-SPDZ v0.4.4, resolved commit `113c4e47dd94bca9ecab029d2f0abe649bea5c52` | Stock MASCOT is a malicious, dishonest-majority protocol; authenticated scalar shares retain both value and MAC shares. | Suitable established arithmetic backend for the stronger corruption model, under its ordinary assumptions and security with abort. This is an upstream protocol claim, not a qualification of our new composition. |
| Existing admission program `0873087b92e66d18f535446f35b5c6ed2438eb629a9d75529bd985f0fda68e54` | Runs a complete-row MASCOT shuffle with checked openings. It publicly opens stable NF/CV before settlement. | Reuse its stock installation and complete-output discipline. Its implemented functionality is a shuffle, not private Groth16 witness/proof generation; active MPC does not repair information deliberately opened by that functionality. |

Primary sources: [co-Groth16 API](https://github.com/TaceoLabs/co-snarks/blob/436f63fa17f2f10ece38c6650df68da99fbc0307/co-circom/co-groth16/src/groth16.rs#L329-L424),
[MP-SPDZ protocol table](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/README.md),
[authenticated share type](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/Share.h#L31-L57).
Local admission source and current RFC-0028/ADR-0065 were read through unchanged
helper09. The documented abort/retry result remains separate bounded evidence;
no retry or attack was rerun here.

## Two concrete incompatibilities

**The field is different.** Existing admission codec
`6b6ef7f294e333f458cffc4c2d5ad18fc59ab084c04b948deecbf2abcac35fa3`
pins BabyJubJub subgroup order
`2736030358979909402780800718157159386076813972158567259200215660948447373041`.
NativeAuthSpend/co-Groth16 arithmetic instead uses BN254 Fr
`21888242871839275222246405745257275088548364400416034343698204186575808495617`.
They are not interchangeable. Do not cast/reduce old shares into Fr or reuse an
old Q-prepared session. The old fixed decimal input width is 76 digits; Fr can
need 77. The selected admission backend explicitly fixes Q in its software,
compiled schedule and runtime checks.

The stock engine supports explicit prime selection at the source/API level:
`ProtocolSetup(bigint prime, Player&)` initializes both arithmetic fields from
that prime. `gfp_<X,4>` spans 193–256-bit moduli, covering both orders. Reusing
the existing stock binary with **fresh Fr bytecode and fresh runtime state**
therefore has a source basis; actual Fr acceptance by that selected binary is
still UNRUN. [Explicit-prime setup](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/ProtocolSetup.h#L36-L52),
[field storage and initialization](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Math/gfp.h#L42-L98).

**The prover driver assumes a different multiplication path.** Its
`local_mul_vec` expressly performs no networking and produces half shares;
`to_half_share` is local, and group half shares are eventually opened.
MASCOT's checked Beaver multiplication needs exchange and authentication.
Exporting only raw value shares into the current REP3/Shamir driver discards
the active-security boundary. A real adapter must change the protocol/driver
contract, keep authentication across nonlinear operations and preserve checked
group openings. A valid final proof is not a substitute for that work.
[Exact driver trait](https://github.com/TaceoLabs/co-snarks/blob/436f63fa17f2f10ece38c6650df68da99fbc0307/co-circom/co-groth16/src/mpc.rs#L71-L120).

## Established group machinery worth reusing

MP-SPDZ already demonstrates authenticated scalar-to-public-curve operations:
its ECDSA code uses `T<P256Element>`, the scalar MAC key, `Direct_MC`, and checked
point openings. This is an implementation pattern to adapt, **not** a shipped
BN254 G1/G2 Groth16 backend. The existing wrapper uses OpenSSL named curves;
BN254 G1/G2 encodings, subgroup checks, field/order agreement and interfaces
remain work. Reuse established BN254 arithmetic rather than inventing a group
or MAC scheme. [Point opening pattern](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/ECDSA/preprocessing.hpp#L53-L101),
[checked public key opening](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/ECDSA/sign.hpp#L139-L163),
[wrapper implementation](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/ECDSA/P256Element.cpp#L12-L21).

Do not copy the ECDSA benchmark launcher as a security profile: it exposes
options disabling correlation checks or MAC generation. The low-level
documentation requires protocol checks before output use and final opening
checks. Preserve those operations in any future wrapper.
[Benchmark options](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/ECDSA/ot-ecdsa-party.hpp#L43-L129),
[low-level check contract](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/doc/low-level.rst#L130-L167).

## Smallest next gate and its limit

`SCALAR-GATE-SPEC-01.md`, `kpi_fr_scalar_gate.mpc` and
`fixture_preflight.py` specify an unexecuted scalar-first component: seven
public synthetic vectors, 28 checked zero residuals, exact Fr and source pins,
fresh bytecode/session/state, all three complete public results. It exercises
sequential authenticated multiplication without any key, proof or real note.
Reject malformed/aliased fixture integers before the engine, rather than
relying on a parser that may reduce them modulo the field. No group wrapper is
available here, so G1/G2, setup and Groth16 remain explicitly out of this gate.

After that gate, adapt and qualify the existing authenticated group pattern
before joining QAP/FFT/MSM/proof operations. NativeAuthSpend's local signing key
must never enter the shared witness. A complete implementation still needs a
fixed authenticated variable map, owner-local inputs, hidden routing/permutation,
the exact public instance prefix, and matching matrix/key/reduction identities.
Owner-labelled witness offsets or proof slots can reveal mapping even when
their field values are secret. The current component matrix controls do not
qualify that distributed protocol.

Finally, keep three separate verdicts: cryptographic witness secrecy against
the stated corruptions; linkage intentionally revealed by public outputs and
abort scheduling; and network/operator independence. MASCOT permits abort and
does not itself provide fairness, guaranteed settlement or anonymity against
amount/timing/cohort observations. No full active privacy, general anonymity,
fee reduction, production safety or financial acceptance is established here.

The current TACEO best-practice search index mentions a 2025 promotion theorem,
but its canonical page returned 404 during this read. No theorem statement,
assumptions or matching implementation was verified, so it is not used to
upgrade the exact pinned API's guarantee. Primary source captures and hashes
are retained in `SOURCE-CAPTURES-03.json`.
