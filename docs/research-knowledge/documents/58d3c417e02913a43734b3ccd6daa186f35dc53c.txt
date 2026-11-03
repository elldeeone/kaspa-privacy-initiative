# Established batching for private assignment validation

Date: 2026-10-28 UTC. Research proposal only; no validation protocol changed.

Decision draft: [ADR-0076](../../../docs/adr/0076-batched-private-assignment-validation.md).
The actual objective is the complete financial MPC batch in
[RFC-0030](../../../docs/rfc/0030-private-batch-construction.md), not an
alternative toy milestone. The earlier
[seven-family source refresh](../../../research/next-session/local-private-payment/privacy-next/PRIVATE-BATCH-SOURCE-REFRESH-2026-10-28.md)
remains the Kaspa/mature-protocol design baseline. This note studies one
additional implementation bottleneck under the same invariants.

## Primary sources and what they establish

The official GitHub `master` commit resolved on 2026-10-28 to
[`113c4e47dd94bca9ecab029d2f0abe649bea5c52`](https://github.com/data61/MP-SPDZ/commit/113c4e47dd94bca9ecab029d2f0abe649bea5c52)
(2026-10-16), the same commit pinned by the retained dependency manifest.
Local public vendor source was checked against the following exact functions.
This source match does not qualify an execution or all dependency settings.

| Source | Relevant result and reuse boundary |
| --- | --- |
| Damgard, Pastro, Smart and Zakarias, *Multiparty Computation from Somewhat Homomorphic Encryption*, [full version, Appendix A.3, On generating the e_i's, p.22](https://eprint.iacr.org/2011/535.pdf#page=22), CRYPTO 2012 | Discusses independent random coefficients, powers of one random element with a polynomial-degree/field-size bound, and a PRG alternative with a computational argument. This is the established batching precedent. Its application is MAC verification; our separate residual zero-test must still be constructed and reviewed. |
| Keller, Orsini and Scholl, *MASCOT*, [full version, authenticated sharing protocol Check, p.14](https://eprint.iacr.org/2016/505.pdf#page=14), CCS 2016 | Uses a fresh public random vector to combine authenticated values and MACs before a MAC check. Its input argument requires inputs to be chosen independently of later random coefficients. It supplies the active authenticated arithmetic foundation, not automatic private R1CS validity. |
| MP-SPDZ [`MAC_Check.hpp`, `MAC_Check_::Check`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/MAC_Check.hpp#L236) | The normal large batch path jointly generates a seed, expands coefficients, combines already opened values/MACs and commit/opens MAC deltas. This verifies authenticity, not that unopened witness residuals equal zero. Its `almost_randomize` coefficients are not an exact-uniform Fr API. |
| MP-SPDZ [`MAC_Check_Base.hpp`, `CheckFor`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/MAC_Check_Base.hpp#L81) | Opens every supplied share, compares clear values and may print the failing clear value. Never call it on our private residuals or aggregate. |
| MP-SPDZ [`SpdzWise.hpp`, `zero_check`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/SpdzWise.hpp#L150) | An existing protocol-specific check multiplies by a random share then calls `CheckFor(0, ...)`. It belongs to different underlying share protocols and opens the masked product. It is not a drop-in MASCOT API or the selected one-bit-only contract. Do not port it without a separate protocol/leakage review. |
| MP-SPDZ [`Subroutines.hpp`, `Create_Random<T>`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Tools/Subroutines.hpp#L13) | Privately samples one field contribution per role, commits all contributions, opens them and sums in the field. Reuse this stock exchange after the complete residual vector is frozen, with a canonical checked contribution adapter; raw `Create_Random<Fr>` is not admitted. It does not reveal local PRNG seeds. |
| MP-SPDZ [`gfp.h`, `randomize`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Math/gfp.h#L235), [`modp.hpp`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Math/modp.hpp#L40), [`random.h`, `randomBnd`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Tools/random.h#L303) | The field sampler masks excess bits and rejects candidates at or above P. Thus it has no modulo-reduction bias in the ideal random-stream model. This does not make a real PRNG information-theoretically random. |
| MP-SPDZ [`random.cpp`, `ReSeed`/`SeedGlobally`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Tools/random.cpp#L38), [`Subroutines.cpp`, `Create_Random_Seed`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Tools/Subroutines.cpp#L133) | `ReSeed` uses libsodium `randombytes_buf`; insecure zero-seed mode exists and must be unreachable. Joint seed generation commit/opens each role's random bytes and XORs them. Secure `GlobalPRNG` uses this path; `SeedGlobally(P,false)` lets role zero choose the seed and is unsuitable. |
| MP-SPDZ [`Commit.cpp`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Tools/Commit.cpp#L6), [`Player.cpp`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Networking/Player.cpp#L611) | Stock commitments bind role, message and a random nonce through a hash. `Broadcast_Receive` accumulates broadcast hashes; `Check_Broadcast` compares them. The coin caller must perform the consistency check before using its result. Commit/reveal does not prevent selective abort. |
| MP-SPDZ [official low-level interface](https://mp-spdz.readthedocs.io/en/latest/low-level.html) and [`ProtocolSet.h`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/ProtocolSet.h) | Required protocol checks precede outputs. Share linear operations act locally; protocol instances are generally not thread-safe. Keep one ordered checked context; extra CPU cores do not justify sharing its mutable protocol state unsafely. |

Paper PDF retrieval returned HTTP403 in this environment. Original SPDZ's
polynomial passage was checked in [Ivan Damgard's author-uploaded full text](https://www.researchgate.net/publication/220336811_Multiparty_Computation_from_Somewhat_Homomorphic_Encryption);
MASCOT's relevant passages were checked through the primary PDF's indexed text.
The source-code claims
above were read directly from the exact upstream files and the public local
vendor copy. This access limit must remain visible; do not describe a missing
full PDF download as a completed whole-paper review.

## Why the public field coin is different from an exposed PRG seed

At this pin, [`random.h`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Tools/random.h#L12)
defines `USE_AES`, and `SEED_SIZE` is one 16-byte AES block. A public 128-bit
seed expanded to an Fr scalar is distinguishable from uniform given the seed;
its scalar image has at most `2^128` elements. A general degree-d polynomial
can put roots at d computable image elements. Therefore one cannot reuse the
ideal `d/P` root bound by simply naming that expanded scalar uniform. This
support-size warning does not demonstrate that a valid financial residual
assignment can realize an arbitrary chosen polynomial.

The stock **direct field coin** commits and reveals each role's sampled Fr
value, not the local seed that generated it. Its ideal argument is elementary:
one honest uniform contribution remains uniform after addition of fixed other
contributions. With a real local CSPRNG, indistinguishability is computational
and commitments must remain hiding until all contributions are committed.
The field rejection sampler gives the exact ideal distribution; it does not
raise AES-128 or hash/MPC security to 230 bits. At least one honest role and
fresh non-rewound randomness are necessary.

Adversarial noncanonical field encodings are not harmless just because the
caller later multiplies in Fr: this pin's generic `unpack` reads limbs without
the external canonical validation contract. The adapter must reject malformed
or out-of-range contributions before accepting the challenge, retain stock
commit/open behavior, and check agreement. No custom commitment or new PRNG
is proposed. Reuse stock `Create_Random<T>` with a wrapper that samples/adds
through Fr, packs fixed canonical bytes and range/length-checks every peer
contribution in `unpack`, before the template sums it. The existing strict scalar
codec is the first reuse candidate. The exact encoding/check adapter is an
implementation-review gate; raw `Create_Random<Fr>` remains inadmissible.

## Whole-vector validity and the one-bit boundary

Freeze `e` as all actual `A(w)*B(w)-C(w)` residuals, every state/trace
`ASSERT_ZERO`, ONE and every actual promised-prefix equality. The same sealed
authenticated assignment must later enter QAP/proof construction. Neither
public program hashes nor completion of a MAC check alone proves `e=0`.

For nonzero fixed `e`, `Z(r)=sum(e[i]*r^i)` is a nonzero polynomial of degree
at most `m-1`. A fresh uniform independent Fr coin makes accidental zero at
most `(m-1)/P`; independently uniform coefficients instead give `1/P`.
Selecting coefficients before inputs or mutating even one residual after
the coin destroys this argument. A fixed public coin permits cancellation,
for example `e=[-r,1]`.

Fermat's theorem gives the full-field private bit `b=1-Z^(P-1)`. Checked
authenticated arithmetic keeps `Z` private; opening only checked `b` releases
one aggregate verdict. This retains the existing implementation's zero-test
primitive once, instead of once per row. Stock integer equality defaults
to a configured bit length ([`types.py`, `sint.__eq__`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Compiler/types.py#L2931),
[`floatingpoint.py`, `EQZ`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Compiler/floatingpoint.py));
it is not automatically an exact arbitrary-Fr check. No suitable stock public
API was found that already provides this complete one-bit-only witness gate.

The present local [`auth_fft.cpp`](../mpc-prover/auth_fft.cpp) exactly checks
all toy residuals, and [`auth_field.cpp`](../mpc-prover/auth_field.cpp) wraps
pending `ProtocolSet::check` plus broadcast checks around public openings.
`open_public_checked` opens its input; it must receive only `b`, never `Z` or
the residual vector. Subsequent proof/group operations keep their own checks.

## Arithmetic estimate and security scope

For the selected Fr, `P-1` has 254 bits and 100 set bits. The present loop uses
253 squarings and 100 multiplies per exact zero-test: 353 authenticated
multiplications. Thirteen million independent exact tests cost 4.589 billion
before AND aggregation. Single-coin batching keeps all row products and
private construction but needs only one such 353-multiplication zero-test,
plus O(m) local field operations for accumulation. This estimate is not a
runtime, preprocessing-size or memory-fit claim.

At m=13,000,000, `(m-1)/P = 5.939261125764183e-70`, approximately `2^-229.96`.
The ideal independent-coefficient error is `1/P`, about `2^-253.60`.
An exposed 128-bit seed's generic m-point support warning is approximately
`2^-104.37`. These numbers were recomputed from the exact public modulus with
Python integer arithmetic and logarithms; no protocol execution occurred.

A corrupt last opener can selectively abort after learning a proposed coin.
The correct bound is per initiated fixed-vector attempt, not conditional on
chosen successful transcripts. Bounded repeated attempts add their error bounds;
unbounded retries, honest-state rewind, assignment replacement and reused coins
need explicit prevention/accounting. Fresh attempt identities alone do not
repair service-history rollback or changed-cohort disclosure. Existing final
SNARK/R0/native verification remains mandatory and cannot erase earlier leaks.

## Review and implementation boundary

The draft selects a **proposal** for direct field coin plus one exact private
zero-test, an immutable `ValidatedAssignment` capability and an absorbing abort
state. Root/independent review must settle canonical field coin decoding,
derived public-prefix binding, capability alias prevention/check epochs,
complete residual coverage and retry persistence before any protocol changes.
The old exact toy and all financial frozen code remain untouched. Passing
future controls would still be bounded implementation evidence, not a proof
of cryptographic correctness, anonymity, recovery or native lifecycle success.
